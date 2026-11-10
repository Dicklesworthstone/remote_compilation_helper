//! Bounded, read-only filesystem evidence for ordinary Node workspace roots.
//!
//! Source-proof callers use `node_workspace` directly with selected bytes.
//! Ordinary dispatch and worker preparation share this reader so they cannot
//! disagree about the package manager or promote an undeclared parent project.
//! Callers must revalidate the returned root under their existing source or
//! preparation ownership before mutation; this function acquires no ownership.

use crate::node_workspace;
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Also bounds the decimal parent distance carried by execution selectors.
pub const MAX_ROOT_PARENTS: usize = 64;

/// Managers whose native root discovery can ignore a nearer independent lock.
#[derive(Clone, Copy, Debug)]
pub enum AncestorWorkspaceManager {
    Bun,
    YarnClassic,
}
const LOCK_NAMES: [&str; 6] = [
    "bun.lock",
    "bun.lockb",
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
];

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    len: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    inode: (u64, u64, i64, i64),
}

impl Identity {
    fn of(metadata: &Metadata) -> Result<Self> {
        ensure!(
            metadata.file_type().is_file(),
            "workspace input is not a regular file"
        );
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
        })
    }
}

fn optional_input(path: &Path) -> Result<Option<Identity>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Identity::of(&metadata)
            .map(Some)
            .with_context(|| format!("inspect workspace input {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    identity: Identity,
    digest: blake3::Hash,
}

fn document(path: &Path) -> Result<Option<(Vec<u8>, Observation)>> {
    let Some(identity) = optional_input(path)? else {
        return Ok(None);
    };
    ensure!(
        identity.len <= node_workspace::MAX_DECLARATION_DOCUMENT_BYTES as u64,
        "workspace declaration exceeds document byte limit"
    );
    #[cfg(unix)]
    let mut file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .context("open workspace declaration without following links or blocking")?,
    );
    #[cfg(not(unix))]
    let mut file = File::open(path).context("open workspace declaration")?;
    ensure!(
        Identity::of(&file.metadata()?)? == identity,
        "workspace declaration changed before read"
    );
    let mut bytes = Vec::new();
    (&mut file).take(identity.len + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == identity.len
            && Identity::of(&file.metadata()?)? == identity
            && optional_input(path)?.as_ref() == Some(&identity),
        "workspace declaration changed during read"
    );
    let digest = blake3::hash(&bytes);
    Ok(Some((bytes, Observation { identity, digest })))
}

fn verify_inputs(observed: &[(PathBuf, Option<Identity>)]) -> Result<()> {
    for (path, identity) in observed {
        ensure!(
            optional_input(path)? == *identity,
            "workspace input changed during root discovery: {}",
            path.display()
        );
    }
    Ok(())
}

/// Return the nearest declared frozen workspace root, or the invocation itself
/// for an independent project. Subdirectories use their nearest package only
/// when that package or its declared workspace has a frozen lock. A lock-free
/// ancestor or no package leaves the invocation unchanged; its existence alone
/// cannot authorize widening a source transfer. A nearer independent lock wins.
/// Symlink/special-file authority is refused.
///
/// `boundary` is a caller-owned ancestry limit, inclusive. Nothing above it is
/// read or selected. Both paths are canonicalized, and an invocation outside
/// the supplied boundary is refused. No manager runs and no file is written.
pub fn resolve_preparation_root(invocation: &Path, boundary: Option<&Path>) -> Result<PathBuf> {
    let invocation = std::fs::canonicalize(invocation).context("resolve invocation directory")?;
    ensure!(
        std::fs::symlink_metadata(&invocation)?.file_type().is_dir(),
        "workspace invocation is not a real directory"
    );
    let boundary = boundary.map(std::fs::canonicalize).transpose()?;
    if let Some(boundary) = &boundary {
        ensure!(
            std::fs::symlink_metadata(boundary)?.file_type().is_dir(),
            "workspace ancestry boundary is not a real directory"
        );
        ensure!(
            invocation.starts_with(boundary),
            "invocation is outside workspace ancestry boundary"
        );
    }
    let mut observed = Vec::new();
    let mut found_package = false;
    for (distance, candidate) in invocation.ancestors().enumerate() {
        ensure!(
            distance <= MAX_ROOT_PARENTS,
            "workspace ancestry exceeds depth limit"
        );
        let manifest = candidate.join("package.json");
        let identity = optional_input(&manifest)?;
        found_package |= identity.is_some();
        observed.push((manifest, identity));
        let mut found_lock = false;
        for name in LOCK_NAMES {
            let path = candidate.join(name);
            let identity = optional_input(&path)?;
            found_lock |= identity.is_some();
            observed.push((path, identity));
        }
        // Locks below the nearest package are not that package's authority.
        // Retain their observations, but keep searching until a package and
        // its own/ancestor lock can be evaluated by the shared pure resolver.
        if !found_lock || !found_package {
            if boundary.as_deref() == Some(candidate) {
                break;
            }
            continue;
        }
        let relative = invocation
            .strip_prefix(candidate)?
            .iter()
            .map(|part| part.to_str().context("workspace member path is not UTF-8"))
            .collect::<Result<Vec<_>>>()?
            .join("/");
        let mut declarations = BTreeMap::new();
        let mut documents = Vec::new();
        let mut total = 0_usize;
        let mut selected = BTreeSet::new();
        for (path, identity) in &observed {
            if identity.is_some() {
                selected.insert(
                    path.strip_prefix(candidate)?
                        .iter()
                        .map(|part| part.to_str().context("workspace input path is not UTF-8"))
                        .collect::<Result<Vec<_>>>()?
                        .join("/"),
                );
            }
        }
        for path in node_workspace::declaration_paths(&relative).map_err(anyhow::Error::msg)? {
            // Include intermediate package manifests too: a command may start
            // in packages/app/src while its nearest package lives at app/.
            let absolute = candidate.join(&path);
            let observation = match document(&absolute)? {
                Some((bytes, observation)) => {
                    total = total
                        .checked_add(bytes.len())
                        .context("workspace declaration size overflow")?;
                    ensure!(
                        total <= node_workspace::MAX_DECLARATION_TOTAL_BYTES,
                        "workspace declarations exceed byte limit"
                    );
                    selected.insert(path.clone());
                    declarations.insert(path, bytes);
                    Some(observation)
                }
                None => None,
            };
            documents.push((absolute, observation));
        }
        let package =
            node_workspace::selected_package_root(&relative, |path| selected.contains(path))
                .map_err(anyhow::Error::msg)?;
        let resolved = package
            .map(|_| node_workspace::resolve_preparation_root(&relative, &selected, &declarations))
            .transpose()
            .map_err(anyhow::Error::msg)?;
        verify_inputs(&observed)?;
        for (path, observation) in documents {
            ensure!(
                document(&path)?.map(|(_, value)| value) == observation,
                "workspace declaration changed during root discovery: {}",
                path.display()
            );
        }
        if let Some(resolved) = resolved {
            let locked = LOCK_NAMES.iter().any(|name| {
                selected.contains(&if resolved.is_empty() {
                    (*name).to_owned()
                } else {
                    format!("{resolved}/{name}")
                })
            });
            if locked {
                // join("") retains a trailing separator in argv even though
                // Path equality ignores it. Native shell boundary checks need
                // the same canonical spelling as the invocation's ancestors.
                return Ok(if resolved.is_empty() {
                    candidate.to_owned()
                } else {
                    candidate.join(resolved)
                });
            }
        }
        return Ok(invocation);
    }
    verify_inputs(&observed)?;
    Ok(invocation)
}

/// Refuse an install that Bun or Yarn Classic could redirect outside its
/// transaction root. Their cwd flags do not pin that root. This is only a
/// read-only safety query; the synthetic lock below selects the existing pure
/// manager-specific membership rules and never grants install/source authority.
/// Native discovery stops at the nearest ancestor workspace declaration even
/// when it does not include this project, so this query has the same boundary.
pub fn verify_install_root(project: &Path, manager: AncestorWorkspaceManager) -> Result<()> {
    let project = project.canonicalize()?;
    let manifest_path = project.join("package.json");
    let (manifest, manifest_observation) =
        document(&manifest_path)?.context("installation root has no regular package.json")?;
    let mut total = manifest.len();
    let mut observed = Vec::new();
    for (distance, candidate) in project.ancestors().skip(1).enumerate() {
        ensure!(
            distance < MAX_ROOT_PARENTS,
            "manager workspace ancestry exceeds depth limit"
        );
        let path = candidate.join("package.json");
        let Some((bytes, observation)) = document(&path)? else {
            observed.push((path, None));
            continue;
        };
        total = total
            .checked_add(bytes.len())
            .context("ancestor declaration size overflow")?;
        ensure!(
            total <= node_workspace::MAX_DECLARATION_TOTAL_BYTES,
            "ancestor workspace declarations exceed byte limit"
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .context("parse ancestor package.json before installation")?;
        let object = value
            .as_object()
            .context("ancestor package.json must be an object")?;
        let workspace = object.get("workspaces");
        observed.push((path, Some(observation)));
        if workspace.is_none() {
            continue;
        }
        ensure!(
            workspace.is_some_and(|value| !value.is_null()),
            "ambiguous ancestor workspace declaration prevents a bounded install"
        );
        let relative = project
            .strip_prefix(candidate)?
            .iter()
            .map(|part| {
                part.to_str()
                    .context("ancestor workspace path is not UTF-8")
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        ensure!(
            !relative
                .split('/')
                .any(|part| matches!(part, "node_modules" | ".git")),
            "manager workspace discovery through package internals is unsupported"
        );
        let member_manifest = format!("{relative}/package.json");
        let lock = match manager {
            AncestorWorkspaceManager::Bun => "bun.lock",
            AncestorWorkspaceManager::YarnClassic => "yarn.lock",
        };
        let selected = BTreeSet::from([
            "package.json".to_owned(),
            member_manifest.clone(),
            lock.to_owned(),
        ]);
        let declarations = BTreeMap::from([
            ("package.json".to_owned(), bytes),
            (member_manifest, manifest.clone()),
        ]);
        let resolved =
            node_workspace::resolve_preparation_root(&relative, &selected, &declarations)
                .map_err(anyhow::Error::msg)?;
        ensure!(
            !resolved.is_empty(),
            "{manager:?} would install in ancestor workspace {} outside the selected preparation root",
            candidate.display()
        );
        break;
    }
    ensure!(
        document(&manifest_path)?.map(|(_, value)| value) == Some(manifest_observation),
        "installation manifest changed during ancestor workspace check"
    );
    for (path, observation) in observed {
        ensure!(
            document(&path)?.map(|(_, value)| value) == observation,
            "ancestor workspace declaration changed before installation"
        );
    }
    Ok(())
}
