//! Close the installed codegen-backend input graph of a native toolchain.
//!
//! rustc can load a backend from lib/rustlib/<host>/codegen-backends, outside
//! the target lib/ trees observed by the std/sysroot reader. Include every
//! installed target's backend tree conservatively: the host probe happens only
//! AFTER this observation. No compiler flag or execution class is admitted here.
//! The existing batch hasher owns terminal-file reads, including hardlink
//! coalescing. This module retains directory/alias generations and named layout.

use super::{CanonicalEncoder, FileSig, Link, TypedDigest, compute, resolve};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 8192;
const DOMAIN_BACKENDS: &str = "rabs.live-dependency.codegen-backends.v1";
type Files = Vec<(PathBuf, FileSig)>;

#[derive(Debug)]
pub(super) struct Closure {
    directories: Files,
    links: Vec<Link>,
    pub(super) layout: TypedDigest,
}

impl Closure {
    pub(super) fn still_current(&self) -> bool {
        let directories_current = || {
            self.directories.iter().all(|(path, signature)| {
                std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.is_dir() && FileSig::of(&metadata) == *signature
                })
            })
        };
        directories_current()
            && self.links.iter().all(Link::still_current)
            && directories_current()
    }
}

struct Inventory<'a> {
    library_root: &'a Path,
    remaining: usize,
    link_budget: usize,
    // Includes rustlib and target parents even when codegen-backends is absent:
    // a later backend installation must invalidate the original observation.
    directories: Files,
    backend_directories: Vec<String>,
    bindings: BTreeMap<String, (String, PathBuf, FileSig)>,
    links: BTreeMap<PathBuf, Link>,
}

impl Inventory<'_> {
    fn relative(&self, path: &Path) -> Result<String, String> {
        path.strip_prefix(self.library_root)
            .map_err(|_| "codegen backend escaped the toolchain library root")?
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| "non-UTF-8 codegen backend path".into())
    }

    fn directory(&mut self, path: &Path, backend: bool) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("codegen backend directory {}: {error}", path.display()))?;
        if !metadata.is_dir() {
            return Err("codegen backend directory is not a real directory".into());
        }
        if backend {
            self.backend_directories.push(self.relative(path)?);
        }
        self.directories
            .push((path.to_path_buf(), FileSig::of(&metadata)));
        Ok(())
    }

    /// Bound allocation while reading, rather than first collecting an
    /// unbounded directory and only then checking the inventory size.
    fn entries(&mut self, path: &Path) -> Result<Vec<PathBuf>, String> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|error| error.to_string())? {
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or("codegen backend inventory exceeds entry bound")?;
            entries.push(entry.map_err(|error| error.to_string())?.path());
        }
        entries.sort();
        Ok(entries)
    }

    fn tree(&mut self, root: PathBuf) -> Result<(), String> {
        let mut pending = vec![root];
        while let Some(directory) = pending.pop() {
            self.directory(&directory, true)?;
            for selected in self.entries(&directory)? {
                let metadata = std::fs::symlink_metadata(&selected)
                    .map_err(|error| format!("codegen backend input: {error}"))?;
                if metadata.is_dir() {
                    pending.push(selected);
                    continue;
                }
                // Every non-directory member must resolve to a regular file.
                // Reuse the reviewed sibling-only resolver; no recursive
                // canonicalize, directory links, or external target reads.
                let (terminal, signature) = resolve(&directory, &selected, &mut self.links)?;
                if self.links.len() > self.link_budget {
                    return Err("combined runtime alias inventory exceeds link bound".into());
                }
                let name = self.relative(&selected)?;
                let target = self.relative(&terminal)?;
                if self
                    .bindings
                    .insert(name, (target, terminal, signature))
                    .is_some()
                {
                    return Err("duplicate codegen backend path".into());
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(Files, Closure), String> {
        self.backend_directories.sort();
        let mut encoder = CanonicalEncoder::new();
        encoder.u64(self.backend_directories.len() as u64);
        for path in &self.backend_directories {
            encoder.str(path);
        }
        encoder.u64(self.bindings.len() as u64);
        for (selected, (terminal, _, _)) in &self.bindings {
            encoder.str(selected).str(terminal);
        }
        encoder.u64(self.links.len() as u64);
        for link in self.links.values() {
            encoder.str(&self.relative(&link.path)?);
            encoder.str(
                link.target
                    .to_str()
                    .ok_or("non-UTF-8 codegen backend alias")?,
            );
        }
        let files: Files = self
            .bindings
            .into_values()
            .map(|(_, path, sig)| (path, sig))
            .collect();
        let closure = Closure {
            directories: self.directories,
            links: self.links.into_values().collect(),
            // Always append this domain, including for an empty inventory. An
            // older key made no claim about backend presence or content.
            layout: compute(DOMAIN_BACKENDS, &encoder.finish()),
        };
        if !closure.still_current() {
            return Err("codegen backend tree changed during observation".into());
        }
        Ok((files, closure))
    }
}

pub(super) fn observe(library_root: &Path, link_budget: usize) -> Result<(Files, Closure), String> {
    let rustlib = library_root.join("rustlib");
    let mut inventory = Inventory {
        library_root,
        remaining: MAX_ENTRIES,
        link_budget,
        directories: Vec::new(),
        backend_directories: Vec::new(),
        bindings: BTreeMap::new(),
        links: BTreeMap::new(),
    };
    inventory.directory(&rustlib, false)?;
    for target in inventory.entries(&rustlib)? {
        let metadata = std::fs::symlink_metadata(&target)
            .map_err(|error| format!("toolchain target: {error}"))?;
        if metadata.is_file() {
            // rustup component/installer records are not backend directories.
            continue;
        }
        inventory.directory(&target, false)?;
        let root = target.join("codegen-backends");
        match std::fs::symlink_metadata(&root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("codegen backend root: {error}")),
            Ok(metadata) if metadata.is_dir() => inventory.tree(root)?,
            Ok(_) => return Err("codegen backend root is not a real directory".into()),
        }
    }
    inventory.finish()
}

#[cfg(test)]
mod tests;
