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
    require(
        safe_relative(directory) && directory.split('/').count() <= 16,
        "cargo_source vendor must be a bounded relative directory inside the approved anchor",
    )
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path.split('/').count() <= 32
        && path
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Preserve Cargo's registry source identity exactly, including the sparse
/// protocol prefix. Accept only unambiguous, credential-free HTTP(S) indexes;
/// this declaration selects already-captured bytes and never grants a fetch.
fn registry_source(index: &str) -> io::Result<String> {
    let (sparse, url) = match index.strip_prefix("sparse+") {
        Some(url) => (true, url),
        None => (false, index),
    };
    let authority_and_path = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| invalid("registry index requires an HTTP(S) or sparse HTTP(S) URL"))?;
    let (authority, path) = authority_and_path
        .split_once('/')
        .ok_or_else(|| invalid("registry index requires an explicit URL path"))?;
    require(
        index.len() <= 2048
            && !authority.is_empty()
            && authority
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
            && !index.contains(['?', '#', '@', '\\', '%'])
            && !index
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
            && path.split('/').all(|part| !matches!(part, "." | ".."))
            && !path.contains("//")
            && (!sparse || url.ends_with('/')),
        "registry index must be bounded, credential-free and unambiguous",
    )?;
    Ok(if sparse {
        index.to_owned()
    } else {
        format!("registry+{index}")
    })
}

fn is_registry_source(source: &str) -> bool {
    source.starts_with("registry+") || source.starts_with("sparse+")
}

fn validate_registry_source(source: &str) -> io::Result<()> {
    let index = source.strip_prefix("registry+").unwrap_or(source);
    require(
        registry_source(index)? == source,
        "registry source has a noncanonical protocol prefix",
    )
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn toml_input(image: &SealedSourceSnapshot, path: &str) -> io::Result<toml::Value> {
    let bytes = image
        .file_bytes("workspace", path)
        .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
        .ok_or_else(|| invalid("missing or oversized captured vendor input"))?;
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("vendor TOML input is not UTF-8"))?;
    // Do not echo arbitrary source/config values into operator diagnostics.
    toml::from_str(text).map_err(|_| invalid("malformed captured vendor TOML input"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checksums {
    package: Value,
    #[serde(default, rename = "$comment")]
    comment: Option<String>,
    #[serde(deserialize_with = "unique_hashes")]
    files: BTreeMap<String, String>,
}

// serde's ordinary map visitor replaces duplicate keys. Checksum evidence must
// instead describe exactly one value for each member, regardless of JSON order.
fn unique_hashes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded, unique file checksum map")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut files = BTreeMap::new();
            while let Some((path, checksum)) = map.next_entry::<String, String>()? {
                if files.len() >= MAX_SOURCE_FILES || files.insert(path, checksum).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive vendor checksum members",
                    ));
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
    checksum: Option<String>,
}

/// Cargo retains the selected Git reference in its source ID, separately from
/// the full revision in Cargo.lock. Neither package names nor directory names
/// are a substitute for that source identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GitSource {
    url: String,
    reference: Option<(String, String)>,
}

fn git_url(url: &str) -> io::Result<()> {
    require(
        url.len() <= 2048
            && ["https://", "http://", "ssh://", "git://", "file://"]
                .iter()
                .any(|scheme| url.starts_with(scheme) && url.len() > scheme.len())
            && !url.contains(['?', '#'])
            && !url.chars().any(|ch| ch.is_whitespace() || ch.is_control()),
        "Git source URL must be bounded and unambiguous",
    )
}

impl GitSource {
    fn parse(source: &str) -> io::Result<Self> {
        require(
            source.len() <= 4096,
            "Git source identity exceeds its bound",
        )?;
        let source = source
            .strip_prefix("git+")
            .ok_or_else(|| invalid("unsupported Cargo source identity"))?;
        let (source, revision) = source
            .rsplit_once('#')
            .ok_or_else(|| invalid("Git lock entry lacks a full revision"))?;
        require(
            git_revision(revision),
            "Git lock entry requires a canonical full revision",
        )?;
        let (url, reference) = if let Some((url, query)) = source.split_once('?') {
            let (kind, value) = query
                .split_once('=')
                .ok_or_else(|| invalid("invalid Git source selector"))?;
            require(
                matches!(kind, "rev" | "branch" | "tag"),
                "unsupported Git source selector",
            )?;
            // Cargo source IDs display references literally, not as URL-form
            // queries. Decoding '+' or '%xx' would conflate different refs.
            require(
                !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
                "invalid Git reference",
            )?;
            require(
                kind != "rev"
                    || value.len() != 40
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || value.eq_ignore_ascii_case(revision),
                "full Git revision selector disagrees with the locked commit",
            )?;
            (url, Some((kind.to_owned(), value.to_owned())))
        } else {
            (source, None)
        };
        git_url(url)?;
        Ok(Self {
            url: url.to_owned(),
            reference,
        })
    }

    fn from_fields(fields: &toml::map::Map<String, toml::Value>) -> io::Result<Self> {
        let url = fields
            .get("git")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("Git source URL missing"))?;
        git_url(url)?;
        let mut reference = None;
        for kind in ["rev", "branch", "tag"] {
            if let Some(value) = fields.get(kind) {
                let value = value
                    .as_str()
                    .filter(|value| {
                        !value.is_empty()
                            && value.len() <= 1024
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or_else(|| invalid("invalid Git source reference"))?;
                require(reference.is_none(), "multiple Git source references")?;
                reference = Some((kind.to_owned(), value.to_owned()));
            }
        }
        Ok(Self {
            url: url.to_owned(),
            reference,
        })
    }
}

#[derive(Debug)]
pub(super) struct SourceReplacements {
    registries: BTreeSet<String>,
    registry_names: BTreeMap<String, String>,
    git: BTreeSet<GitSource>,
    directory: PathBuf,
}

impl SourceReplacements {
    pub(super) fn check_local_package_path(&self, path: &Path, pattern: bool) -> io::Result<()> {
        let pattern = pattern
            && path.components().any(|part| {
                part.as_os_str()
                    .to_string_lossy()
                    .contains(['*', '?', '[', ']'])
            });
        let prefix = if pattern {
            path.components()
                .take_while(|part| {
                    !part
                        .as_os_str()
                        .to_string_lossy()
                        .contains(['*', '?', '[', ']'])
                })
                .collect::<PathBuf>()
        } else {
            path.to_path_buf()
        };
        require(
            !prefix.starts_with(&self.directory)
                && (!pattern || !self.directory.starts_with(&prefix)),
            "local Cargo package selection may not enter the verified vendor directory",
        )
    }

    pub(super) fn check_dependency(
        &self,
        fields: &toml::map::Map<String, toml::Value>,
    ) -> io::Result<()> {
        require(
            !fields.contains_key("path"),
            "Git dependency cannot also select a local path",
        )?;
        require(
            self.git.contains(&GitSource::from_fields(fields)?),
            "Git dependency has no exact captured directory-source replacement",
        )
    }

    pub(super) fn check_registry_dependency(
        &self,
        fields: &toml::map::Map<String, toml::Value>,
    ) -> io::Result<()> {
        require(
            !fields.contains_key("git")
                && !(fields.contains_key("registry") && fields.contains_key("registry-index")),
            "dependency contains conflicting registry/Git selectors",
        )?;
        let source = if let Some(name) = fields.get("registry") {
            let name = name
                .as_str()
                .ok_or_else(|| invalid("dependency registry name must be a string"))?;
            self.registry_names
                .get(name)
                .cloned()
                .ok_or_else(|| invalid("dependency registry has no captured index declaration"))?
        } else {
            let index = fields
                .get("registry-index")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("dependency registry index must be a string"))?;
            registry_source(index)?
        };
        require(
            self.registries.contains(&source),
            "dependency registry has no exact captured directory-source replacement",
        )
    }

    fn check_source(&self, source: &str) -> io::Result<()> {
        if is_registry_source(source) {
            validate_registry_source(source)?;
            require(
                self.registries.contains(source),
                "registry package has no captured source replacement",
            )
        } else {
            require(
                self.git.contains(&GitSource::parse(source)?),
                "locked Git source has no exact captured directory-source replacement",
            )
        }
    }
}

pub(super) type LockedPackages = BTreeSet<(String, String, String)>;

/// Constructed only from one retained image. It does not outlive or authorize
/// another snapshot. Directory/package names are not inferred from name-version
/// strings; Cargo vendor allows arbitrary unambiguous package directory names.
#[derive(Debug)]
pub(super) struct VendoredSources {
    directory: String,
    config: String,
    packages: BTreeMap<String, Package>,
    pub(super) sources: SourceReplacements,
}

impl VendoredSources {
    pub(super) fn verify(
        image: &SealedSourceSnapshot,
        manifest: &str,
        directory: &str,
    ) -> io::Result<Self> {
        validate_directory(directory)?;
        require(
            !Path::new(manifest).starts_with(directory),
            "selected Cargo manifest is inside its vendor source",
        )?;
        let captured = image
            .manifest("workspace")
            .ok_or_else(|| invalid("missing captured Cargo anchor"))?;
        let mut configs = Vec::new();
        let mut file_count = 0_usize;
        let mut members: BTreeMap<String, BTreeMap<String, &str>> = BTreeMap::new();
        let prefix = format!("{directory}/");
        for (path, kind) in &captured.members {
            require(
                !matches!(kind, MemberKind::Symlink { .. }),
                "vendored source capture contains a symlink",
            )?;
            if !matches!(kind, MemberKind::Regular { .. }) {
                continue;
            }
            file_count += 1;
            require(
                file_count <= MAX_SOURCE_FILES,
                "captured anchor exceeds the source file-count bound",
            )?;
            if let Some(relative) = path.strip_prefix(&prefix) {
                let (package, member) = relative.split_once('/').ok_or_else(|| {
                    invalid("vendor source contains a file outside a package directory")
                })?;
                require(
                    !package.starts_with('.') && safe_relative(member),
                    "unsafe or hidden vendor package member",
                )?;
                let package_root = format!("{directory}/{package}");
                members
                    .entry(package_root)
                    .or_default()
                    .insert(member.to_owned(), path);
                require(
                    members.len() <= MAX_PACKAGES,
                    "vendor package count exceeds its bound",
                )?;
            } else if is_cargo_config(Path::new(path)) {
                configs.push(path.clone());
            }
        }
        require(
            !members.is_empty(),
            "explicit vendor directory contains no captured packages",
        )?;
        require(
            configs.len() == 1,
            "vendor preparation requires one captured source-replacement config and no other Cargo config layers",
        )?;
        let config = configs
            .pop()
            .ok_or_else(|| invalid("missing vendor configuration"))?;
        let config_base = Path::new(&config)
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid("invalid vendor configuration path"))?;
        require(
            Path::new(manifest)
                .parent()
                .is_some_and(|parent| parent.starts_with(config_base)),
            "vendor source configuration is not an ancestor of the selected manifest",
        )?;
        let sources = validate_config(&toml_input(image, &config)?, config_base, directory)?;

        let mut packages = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut count = 0_usize;
        for (root, files) in members {
            count = count
                .checked_add(files.len())
                .filter(|count| *count <= MAX_SOURCE_FILES)
                .ok_or_else(|| invalid("vendor file count exceeds the source bound"))?;
            let checksum_path = files
                .get(CHECKSUM_FILE)
                .ok_or_else(|| invalid("vendor package lacks .cargo-checksum.json"))?;
            let bytes = image
                .file_bytes("workspace", checksum_path)
                .filter(|bytes| bytes.len() <= OUTPUT_LIMIT as usize)
                .ok_or_else(|| invalid("vendor checksum file unavailable or oversized"))?;
            let checksums: Checksums = serde_json::from_slice(bytes)
                .map_err(|_| invalid("malformed or duplicate vendor checksum metadata"))?;
            let checksum = match &checksums.package {
                Value::Null => None,
                Value::String(checksum) if canonical_hash(checksum) => Some(checksum.clone()),
                _ => {
                    return Err(invalid(
                        "vendor package checksum must be null for Git or canonical SHA-256 for a registry",
                    ));
                }
            };
            require(
                checksums
                    .comment
                    .as_ref()
                    .is_none_or(|comment| comment.len() <= 4096),
                "oversized vendor checksum comment",
            )?;
            require(
                checksum.is_some() || !sources.git.is_empty(),
                "null package checksum requires a declared Git replacement",
            )?;
            require(
                checksums.files.len() + 1 == files.len()
                    && checksums.files.contains_key("Cargo.toml"),
                "vendor checksums do not cover the exact captured package file set",
            )?;
            for (name, expected) in &checksums.files {
                require(
                    safe_relative(name) && name != CHECKSUM_FILE && canonical_hash(expected),
                    "invalid vendor checksum path or SHA-256",
                )?;
                let captured_path = files
                    .get(name)
                    .ok_or_else(|| invalid("checksummed vendor member missing from capture"))?;
                let bytes = image
                    .file_bytes("workspace", captured_path)
                    .ok_or_else(|| invalid("checksummed vendor bytes unavailable"))?;
                require(
                    hash(bytes) == *expected,
                    "vendored file checksum differs from captured bytes",
                )?;
            }
            let package_manifest = files
                .get("Cargo.toml")
                .ok_or_else(|| invalid("vendor package manifest missing"))?;
            let value = toml_input(image, package_manifest)?;
            // Published package manifests must not escape their own package via
            // readme, build-script, target or path-dependency declarations.
            super::validate_manifest_paths(
                Path::new(""),
                &value,
                Some(&sources),
                checksum.is_none(),
            )?;
            let package = value
                .get("package")
                .and_then(toml::Value::as_table)
                .ok_or_else(|| invalid("vendor manifest does not describe a package"))?;
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| invalid("vendor package name missing"))?;
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .filter(|version| !version.is_empty())
                .ok_or_else(|| invalid("vendor package version must be explicit"))?;
            require(
                identities.insert((name.to_owned(), version.to_owned())),
                "duplicate vendor package name and version",
            )?;
            packages.insert(
                root,
                Package {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    checksum,
                },
            );
        }
        Ok(Self {
            directory: directory.to_owned(),
            config,
            packages,
            sources,
        })
    }

    pub(super) fn contains(&self, path: &str) -> bool {
        Path::new(path).starts_with(&self.directory)
    }

    pub(super) fn allows_config(&self, path: &str) -> bool {
        path == self.config || self.contains(path)
    }

    pub(super) fn validate_lock_sources(&self, lock: &toml::Value) -> io::Result<()> {
        validate_lock_sources(lock)?;
        for package in lock["package"]
            .as_array()
            .ok_or_else(|| invalid("missing package lock"))?
        {
            if let Some(source) = package.get("source").and_then(toml::Value::as_str) {
                self.sources.check_source(source)?;
            }
        }
        Ok(())
    }

    /// Check the actual metadata workspace's lockfile, not the first similarly
    /// named file under the approved anchor. Every locked registry package must
    /// have a byte-verified directory and the same package checksum.
    pub(super) fn bind_lock(
        &self,
        image: &SealedSourceSnapshot,
        lock: &Path,
    ) -> io::Result<LockedPackages> {
        let lock = lock
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 vendor lockfile path"))?;
        let value = toml_input(image, lock)?;
        self.validate_lock_sources(&value)?;
        let packages = value
            .get("package")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| invalid("vendor preparation requires a package lockfile"))?;
        let mut seen = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for package in packages {
            let Some(source) = package.get("source") else {
                continue;
            };
            let source = source
                .as_str()
                .ok_or_else(|| invalid("locked package source must be a string"))?;
            self.sources.check_source(source)?;
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("locked registry package name missing"))?;
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("locked registry package version missing"))?;
            require(
                identities.insert((name.to_owned(), version.to_owned())),
                "ambiguous locked package sources for one vendor identity",
            )?;
            require(
                seen.insert((name.to_owned(), version.to_owned(), source.to_owned())),
                "duplicate locked package",
            )?;
            let found = self
                .packages
                .values()
                .find(|candidate| candidate.name == name && candidate.version == version)
                .ok_or_else(|| {
                    invalid("locked registry package is absent from the verified vendor source")
                })?;
            require(
                package.get("checksum").and_then(toml::Value::as_str) == found.checksum.as_deref(),
                "vendor package checksum differs from the workspace lockfile",
            )?;
        }
        Ok(seen)
    }

    pub(super) fn check_package(
        &self,
        root: &Path,
        package: &Value,
        locked: &LockedPackages,
    ) -> io::Result<()> {
        let path = package["manifest_path"]
            .as_str()
            .map(Path::new)
            .ok_or_else(|| invalid("resolved vendor package manifest missing"))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| invalid("resolved package escaped the captured anchor"))?;
        let parent = relative
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| invalid("resolved package parent missing"))?;
        if package.get("source").is_some_and(Value::is_null) {
            return require(
                !self.contains(parent),
                "vendor directory cannot be reclassified as a local path package",
            );
        }
        let source = package["source"]
            .as_str()
            .ok_or_else(|| invalid("resolved package source missing"))?;
        self.sources.check_source(source)?;
        let expected = self.packages.get(parent).ok_or_else(|| {
            invalid("Cargo resolved registry package outside the verified vendor source")
        })?;
        require(
            relative
                .file_name()
                .is_some_and(|name| name == "Cargo.toml")
                && package["name"].as_str() == Some(expected.name.as_str())
                && package["version"].as_str() == Some(expected.version.as_str()),
            "resolved vendor package identity differs from its captured manifest",
        )?;
        require(
            locked.contains(&(
                expected.name.clone(),
                expected.version.clone(),
                source.to_owned(),
            )),
            "Cargo resolved a vendor package absent from the workspace lockfile",
        )?;
        let package_root = path
            .parent()
            .ok_or_else(|| invalid("resolved package has no parent"))?;
        for target in package["targets"]
            .as_array()
            .ok_or_else(|| invalid("resolved vendor targets missing"))?
        {
            require(
                target["src_path"]
                    .as_str()
                    .is_some_and(|path| Path::new(path).starts_with(package_root)),
                "resolved vendor target is outside its package",
            )?;
        }
        Ok(())
    }
}

fn validate_config(
    value: &toml::Value,
    base: &Path,
    directory: &str,
) -> io::Result<SourceReplacements> {
    let top = value
        .as_table()
        .filter(|top| {
            top.keys()
                .all(|key| matches!(key.as_str(), "source" | "registries"))
        })
        .ok_or_else(|| {
            invalid("vendor config may contain only source replacement and registry indexes")
        })?;
    let sources = top
        .get("source")
        .and_then(toml::Value::as_table)
        .filter(|sources| sources.len() >= 2 && sources.len() <= MAX_PACKAGES + 2)
        .ok_or_else(|| {
            invalid("vendor config requires bounded original sources and one directory source")
        })?;
    let directories: Vec<_> = sources
        .iter()
        .filter(|(_, source)| source.get("directory").is_some())
        .collect();
    let [(name, replacement)] = directories.as_slice() else {
        return Err(invalid(
            "vendor config requires exactly one directory source",
        ));
    };
    require(
        name.as_str() != "crates-io",
        "original source cannot be a directory replacement",
    )?;
    let replacement = replacement
        .as_table()
        .filter(|source| source.len() == 1)
        .ok_or_else(|| {
            invalid("vendor replacement must be one directory source without aliases")
        })?;
    let configured = replacement
        .get("directory")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| invalid("vendor replacement directory missing"))?;
    // Cargo resolves file-config paths relative to the parent of .cargo, not
    // relative to cwd or the .cargo directory itself (Cargo config reference).
    require(
        contained_relative(base, configured)? == Path::new(directory),
        "Cargo config directory differs from the explicitly approved vendor directory",
    )?;
    let mut result = SourceReplacements {
        registries: BTreeSet::new(),
        registry_names: BTreeMap::new(),
        git: BTreeSet::new(),
        directory: PathBuf::from(directory),
    };
    for (original_name, original) in sources {
        if original_name == *name {
            continue;
        }
        let fields = original
            .as_table()
            .ok_or_else(|| invalid("source replacement must be a table"))?;
        require(
            fields.get("replace-with").and_then(toml::Value::as_str) == Some(name.as_str()),
            "source replacement must refer directly to the approved directory",
        )?;
        if original_name == "crates-io" {
            require(fields.len() == 1, "invalid crates.io source replacement")?;
            require(
                result.registries.insert(CRATES_IO.to_owned()),
                "duplicate registry source replacement identity",
            )?;
            result
                .registry_names
                .insert("crates-io".to_owned(), CRATES_IO.to_owned());
        } else if let Some(index) = fields.get("registry") {
            require(
                fields.len() == 2,
                "registry source replacement requires only registry and replace-with",
            )?;
            let source = registry_source(
                index
                    .as_str()
                    .ok_or_else(|| invalid("registry source index must be a string"))?,
            )?;
            require(
                result.registries.insert(source),
                "duplicate registry source replacement identity",
            )?;
        } else {
            require(
                fields.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "git" | "rev" | "tag" | "branch" | "replace-with"
                    )
                }),
                "unsupported Git source replacement fields",
            )?;
            let source = GitSource::from_fields(fields)?;
            // Cargo matches a Git replacement by these declared fields; the
            // table name is an alias, including in valid hand-named configs.
            require(
                result.git.insert(source),
                "duplicate Git source replacement identity",
            )?;
        }
    }
    if let Some(registries) = top.get("registries") {
        let registries = registries
            .as_table()
            .filter(|registries| registries.len() <= MAX_PACKAGES)
            .ok_or_else(|| invalid("captured registry declarations must be a bounded table"))?;
        for (name, registry) in registries {
            require(
                !name.is_empty()
                    && name.len() <= 128
                    && name != "crates-io"
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
                "invalid or reserved alternate registry name",
            )?;
            let fields = registry
                .as_table()
                .filter(|fields| fields.len() == 1)
                .ok_or_else(|| {
                    invalid("captured registry accepts only its index, not credentials or helpers")
                })?;
            let index = fields
                .get("index")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("captured registry index missing"))?;
            let source = registry_source(index)?;
            require(
                result.registries.contains(&source),
                "alternate registry has no exact captured directory-source replacement",
            )?;
            result.registry_names.insert(name.clone(), source);
        }
    }
    Ok(result)
}

pub(super) fn validate_lock_sources(lock: &toml::Value) -> io::Result<()> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .filter(|packages| !packages.is_empty() && packages.len() <= MAX_PACKAGES)
        .ok_or_else(|| invalid("Cargo vendor lockfile package set is missing or excessive"))?;
    for package in packages {
        if let Some(source) = package.get("source") {
            let source = source
                .as_str()
                .ok_or_else(|| invalid("locked package source must be a string"))?;
            if is_registry_source(source) {
                validate_registry_source(source)?;
                require(
                    package
                        .get("checksum")
                        .and_then(toml::Value::as_str)
                        .is_some_and(canonical_hash),
                    "locked registry package checksum missing or noncanonical",
                )?;
            } else {
                GitSource::parse(source)?;
                require(
                    package.get("checksum").is_none(),
                    "Git lock entry cannot claim a registry archive checksum",
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
