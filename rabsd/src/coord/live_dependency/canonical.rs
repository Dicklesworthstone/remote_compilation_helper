//! Retained backing paths for the coordinator-owned canonical Cargo driver.
//!
//! Compiler arguments, dep-info and action keys keep their namespace-visible
//! names. Only filesystem observation and private output installation use this
//! capability. It is constructed by the driver, never decoded from a wrapper
//! frame, and owns the operation directory until every request has drained.

use rabs_key::live_dependency::{
    DependencyActionPlan, DependencyDirectoryFact, ExternFact, PlannedExtern,
};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ROOTS: [&str; 5] = [
    "/__rabs/workspace",
    "/__rabs/cargo-home",
    "/__rabs/toolchain",
    "/__rabs/out/cargo",
    "/__rabs/home",
];

#[derive(Debug)]
struct Mount {
    visible: PathBuf,
    backing: PathBuf,
    device: u64,
    inode: u64,
}

/// Filesystem capability retained by one canonical Cargo operation.
///
/// There is deliberately no public constructor or deserializer. An absolute
/// path supplied by a wrapper cannot select a coordinator filesystem root.
#[derive(Debug)]
pub struct CanonicalPaths {
    _owner: Arc<tempfile::TempDir>,
    mounts: Vec<Mount>,
}

fn ordinary_absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.starts_with('/')
            && text.len() > 1
            && !text.contains(['\\', '\0'])
            && text
                .split('/')
                .skip(1)
                .all(|part| !matches!(part, "" | "." | ".."))
    })
}

fn path_text(path: PathBuf) -> Result<String, String> {
    path.into_os_string()
        .into_string()
        .map_err(|_| "canonical backing path is not UTF-8".to_owned())
}

impl CanonicalPaths {
    pub(crate) fn new(
        owner: Arc<tempfile::TempDir>,
        mappings: Vec<(PathBuf, PathBuf)>,
    ) -> Result<Arc<Self>, String> {
        let owned = owner.path();
        if !ordinary_absolute(owned) {
            return Err("canonical operation root is not an ordinary absolute path".into());
        }
        let root = std::fs::symlink_metadata(owned).map_err(|error| error.to_string())?;
        if !root.is_dir()
            || root.uid() != rustix::process::geteuid().as_raw()
            || root.mode() & 0o077 != 0
        {
            return Err("canonical operation root must be an owned private directory".into());
        }
        let mut visible = BTreeSet::new();
        let mut mounts: Vec<Mount> = Vec::new();
        for (logical, backing) in mappings {
            if !ROOTS.iter().any(|root| logical == Path::new(root))
                || !visible.insert(logical.clone())
                || !ordinary_absolute(&backing)
                || backing == owned
                || !backing.starts_with(owned)
                || mounts.iter().any(|mount| {
                    backing.starts_with(&mount.backing) || mount.backing.starts_with(&backing)
                })
            {
                return Err("canonical mount mapping is outside or aliases its owned roots".into());
            }
            for ancestor in backing
                .ancestors()
                .take_while(|path| path.starts_with(owned))
            {
                let metadata =
                    std::fs::symlink_metadata(ancestor).map_err(|error| error.to_string())?;
                if !metadata.is_dir()
                    || metadata.uid() != root.uid()
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(
                        "canonical backing ancestor is not an owned ordinary directory".into(),
                    );
                }
            }
            let metadata =
                std::fs::symlink_metadata(&backing).map_err(|error| error.to_string())?;
            mounts.push(Mount {
                visible: logical,
                backing,
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }
        if visible.len() != ROOTS.len() {
            return Err("canonical driver did not retain every declared mount".into());
        }
        Ok(Arc::new(Self {
            _owner: owner,
            mounts,
        }))
    }

    fn verify_mount(mount: &Mount) -> Result<(), String> {
        let metadata =
            std::fs::symlink_metadata(&mount.backing).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) != (mount.device, mount.inode) {
            return Err("canonical backing root was replaced".into());
        }
        Ok(())
    }

    /// Resolve a visible name through this operation's retained mount table.
    /// Unknown namespaces, traversal, replaced roots and symlinks are refused.
    pub(crate) fn physical(&self, path: &Path) -> Result<PathBuf, String> {
        if !ordinary_absolute(path) {
            return Err("canonical request path is not normalized and absolute".into());
        }
        let (mount, relative) = self
            .mounts
            .iter()
            .find_map(|mount| path.strip_prefix(&mount.visible).ok().map(|r| (mount, r)))
            .ok_or("canonical request names an undeclared mount")?;
        Self::verify_mount(mount)?;
        let mut physical = mount.backing.clone();
        for component in relative.components() {
            physical.push(component.as_os_str());
            match std::fs::symlink_metadata(&physical) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err("canonical backing path contains a symlink".into());
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Self::verify_mount(mount)?;
        Ok(physical)
    }

    /// Recover the visible name of a path observed through a retained mount.
    pub(crate) fn logical(&self, path: &Path) -> Result<PathBuf, String> {
        if !ordinary_absolute(path) {
            return Err("observed canonical backing path is not normalized".into());
        }
        let (mount, relative) = self
            .mounts
            .iter()
            .find_map(|mount| path.strip_prefix(&mount.backing).ok().map(|r| (mount, r)))
            .ok_or("observed input is outside the retained canonical mounts")?;
        Self::verify_mount(mount)?;
        Ok(mount.visible.join(relative))
    }

    /// An I/O-only projection. Never pass this copy to an action-key builder or
    /// use it to reconstruct compiler argv, environment, dep-info or transcripts.
    pub(crate) fn project_plan(
        &self,
        logical: &DependencyActionPlan,
    ) -> Result<DependencyActionPlan, String> {
        if logical.generated_root.is_some() {
            return Err("canonical dependency bridge does not admit generated inputs".into());
        }
        let translate = |value: &str| path_text(self.physical(Path::new(value))?);
        let mut physical = logical.clone();
        physical.compiler = translate(&logical.compiler)?;
        physical.cwd = translate(&logical.cwd)?;
        physical.out_dir = translate(&logical.out_dir)?;
        physical.package_root = translate(&logical.package_root)?;
        physical.source_root = translate(&logical.source_root)?;
        physical.dependency_dirs = logical
            .dependency_dirs
            .iter()
            .map(|path| translate(path))
            .collect::<Result<_, _>>()?;
        for external in &mut physical.externs {
            if let PlannedExtern::File { path, .. } = external {
                *path = translate(path)?;
            }
        }
        Ok(physical)
    }

    pub(crate) fn dependency_facts(
        &self,
        physical: &[DependencyDirectoryFact],
    ) -> Result<Vec<DependencyDirectoryFact>, String> {
        physical
            .iter()
            .map(|directory| {
                Ok(DependencyDirectoryFact {
                    path: path_text(self.logical(Path::new(&directory.path))?)?,
                    artifacts: directory
                        .artifacts
                        .iter()
                        .map(|artifact| {
                            Ok(ExternFact {
                                path: path_text(self.logical(Path::new(&artifact.path))?)?,
                                content_digest: artifact.content_digest.clone(),
                            })
                        })
                        .collect::<Result<_, String>>()?,
                })
            })
            .collect()
    }

    /// Probe the retained native compiler with loader paths from the same
    /// captured toolchain. These host probe values never replace the compiler's
    /// canonical execution environment or enter its action descriptor.
    pub(crate) fn probe_environment(
        &self,
        environment: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String> {
        environment
            .iter()
            .map(|(name, value)| {
                let value = if matches!(
                    name.as_str(),
                    "LD_LIBRARY_PATH" | "DYLD_LIBRARY_PATH" | "DYLD_FALLBACK_LIBRARY_PATH"
                ) {
                    value
                        .split(':')
                        .map(|path| {
                            if path.starts_with("/__rabs/") {
                                path_text(self.physical(Path::new(path))?)
                            } else {
                                Ok(path.to_owned())
                            }
                        })
                        .collect::<Result<Vec<_>, String>>()?
                        .join(":")
                } else {
                    value.clone()
                };
                Ok((name.clone(), value))
            })
            .collect()
    }

    pub(crate) fn backing_roots(&self) -> Vec<String> {
        self.mounts
            .iter()
            .map(|mount| mount.backing.to_string_lossy().into_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    fn fixture() -> (Arc<tempfile::TempDir>, Arc<CanonicalPaths>) {
        let owner = Arc::new(tempfile::tempdir().unwrap());
        let mappings = ROOTS
            .iter()
            .enumerate()
            .map(|(index, root)| {
                let backing = owner.path().join(index.to_string());
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&backing)
                    .unwrap();
                (PathBuf::from(root), backing)
            })
            .collect();
        let paths = CanonicalPaths::new(Arc::clone(&owner), mappings).unwrap();
        (owner, paths)
    }

    #[test]
    fn canonical_paths_use_component_boundaries_and_keep_the_owner_alive() {
        let (owner, paths) = fixture();
        let root = owner.path().to_path_buf();
        let visible = Path::new("/__rabs/out/cargo/debug/deps/liba.rmeta");
        let backing = paths.physical(visible).unwrap();
        assert_eq!(backing, root.join("3/debug/deps/liba.rmeta"));
        assert_eq!(paths.logical(&backing).unwrap(), visible);
        drop(owner);
        assert!(root.is_dir());
        for path in [
            "/__rabs/out/cargo-other/file",
            "/__rabs/out/cargo/../state",
            "/__rabs/out/cargo/./file",
            "/__rabs/out/cargo//file",
            "/etc/passwd",
        ] {
            assert!(paths.physical(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn canonical_paths_refuse_symlinks_and_replaced_mount_roots() {
        use std::os::unix::fs::symlink;
        let (owner, paths) = fixture();
        symlink(owner.path().join("1"), owner.path().join("0/alias")).unwrap();
        assert!(
            paths
                .physical(Path::new("/__rabs/workspace/alias/Cargo.toml"))
                .is_err()
        );
        std::fs::rename(owner.path().join("0"), owner.path().join("old-source")).unwrap();
        std::fs::create_dir(owner.path().join("0")).unwrap();
        assert!(
            paths
                .physical(Path::new("/__rabs/workspace/lib.rs"))
                .is_err()
        );
    }

    #[test]
    fn canonical_mounts_cannot_select_ambient_or_overlapping_backing_paths() {
        let (owner, _) = fixture();
        let mut mappings: Vec<_> = ROOTS
            .iter()
            .enumerate()
            .map(|(index, root)| (PathBuf::from(root), owner.path().join(index.to_string())))
            .collect();
        mappings[1].1 = owner.path().join("0/child");
        std::fs::create_dir(&mappings[1].1).unwrap();
        assert!(CanonicalPaths::new(Arc::clone(&owner), mappings.clone()).is_err());
        mappings[1].1 = std::env::temp_dir();
        assert!(CanonicalPaths::new(owner, mappings).is_err());
    }
}
