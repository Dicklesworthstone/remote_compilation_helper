//! Closed, bounded ELF runtime aliases inside one real toolchain lib directory.
//!
//! A SONAME link is not a missing library. Resolve only exact sibling names,
//! retain every link generation, and hash the final regular files through the
//! existing no-follow streaming path. The key binds the selected names and
//! link graph; inode/time observations remain freshness evidence only. This
//! does not admit directory links, external libraries, or linked sysroot trees.
//! Installed codegen backends join this same observation and hashing batch:
//! their bytes are compiler inputs, not implied by rustc's version string.

mod codegen_backends;

use super::{CanonicalEncoder, FileSig, TypedDigest, compute, lstat_regular, toolchain_entries};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_LINK_DEPTH: usize = 16;
const MAX_LINKS: usize = 256;
const DOMAIN_RUNTIME_ALIASES: &str = "rabs.live-dependency.runtime-aliases.v1";

#[derive(Debug, PartialEq, Eq)]
struct Link {
    path: PathBuf,
    target: PathBuf,
    signature: FileSig,
}

impl Link {
    fn read(path: &Path, signature: FileSig) -> Result<Self, String> {
        // Linux bounds link bodies, but bound the admitted basename ourselves
        // before reading. No canonicalize/open follows an unobserved chain.
        if signature.size == 0 || signature.size > 255 {
            return Err("runtime alias target exceeds sibling-name bound".into());
        }
        let target = std::fs::read_link(path)
            .map_err(|error| format!("read runtime alias {}: {error}", path.display()))?;
        let name = target.to_str().ok_or("non-UTF-8 runtime alias target")?;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\\'])
            || name.len() > 255
        {
            return Err("runtime alias must name an exact sibling file".into());
        }
        let observed = Self {
            path: path.to_path_buf(),
            target,
            signature,
        };
        if !observed.still_current() {
            return Err("runtime alias changed while observing its target".into());
        }
        Ok(observed)
    }

    fn still_current(&self) -> bool {
        let identity_matches = || {
            std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
                metadata.file_type().is_symlink() && FileSig::of(&metadata) == self.signature
            })
        };
        identity_matches()
            && std::fs::read_link(&self.path).is_ok_and(|target| target == self.target)
            && identity_matches()
    }
}

/// Retained alongside the original toolchain observation, never replaced by a
/// newer shared memo. The optional alias digest distinguishes linked profiles.
/// The backend layout is always bound, even when no backends are installed, so
/// entries created before backend observation cannot become hits in this lane.
#[derive(Debug)]
pub(super) struct Aliases {
    links: Vec<Link>,
    layout: Option<TypedDigest>,
    backends: codegen_backends::Closure,
}

impl Aliases {
    pub(super) fn still_current(&self) -> bool {
        self.backends.still_current()
            && self.links.iter().all(Link::still_current)
            && self.backends.still_current()
    }

    pub(super) fn bind_layout(&self, runtime_digests: &mut Vec<TypedDigest>) {
        if let Some(layout) = &self.layout {
            runtime_digests.push(layout.clone());
        }
        runtime_digests.push(self.backends.layout.clone());
    }
}

#[derive(Debug)]
pub(super) struct Observation {
    /// Terminal regular paths in the original selected-runtime-name order.
    /// Duplicates are intentional: the batch hasher already coalesces reads
    /// by file identity without changing the canonical roles/order.
    pub(super) files: Vec<(PathBuf, FileSig)>,
    pub(super) aliases: Aliases,
}

fn resolve(
    directory: &Path,
    selected: &Path,
    links: &mut BTreeMap<PathBuf, Link>,
) -> Result<(PathBuf, FileSig), String> {
    let mut path = selected.to_path_buf();
    let mut visited = BTreeSet::new();
    for depth in 0..=MAX_LINK_DEPTH {
        if !visited.insert(path.clone()) {
            return Err("runtime alias cycle".into());
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("toolchain runtime {}: {error}", path.display()))?;
        if metadata.is_file() {
            return Ok((path, FileSig::of(&metadata)));
        }
        if !metadata.file_type().is_symlink() {
            return Err(format!(
                "non-regular runtime alias target: {}",
                path.display()
            ));
        }
        if depth == MAX_LINK_DEPTH {
            return Err("runtime alias chain exceeds depth bound".into());
        }
        let observed = Link::read(&path, FileSig::of(&metadata))?;
        let next = directory.join(&observed.target);
        if let Some(previous) = links.get(&path) {
            if previous != &observed {
                return Err("runtime alias changed between selected libraries".into());
            }
        } else {
            if links.len() >= MAX_LINKS {
                return Err("runtime alias inventory exceeds link bound".into());
            }
            links.insert(path, observed);
        }
        path = next;
    }
    Err("runtime alias chain exceeds depth bound".into())
}

pub(super) fn observe(directory: &Path) -> Result<Observation, String> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| format!("runtime library directory: {error}"))?;
    if !metadata.is_dir() {
        return Err("runtime library root is not a real directory".into());
    }
    let before = FileSig::of(&metadata);
    let mut files = Vec::new();
    let mut bindings = Vec::new();
    let mut links = BTreeMap::new();
    for selected in toolchain_entries(directory)? {
        let name = selected
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("non-UTF-8 toolchain runtime entry")?;
        if !name.contains(".so") {
            continue;
        }
        let (path, signature) = resolve(directory, &selected, &mut links)?;
        let terminal = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("non-UTF-8 runtime terminal file")?;
        bindings.push((name.to_owned(), terminal.to_owned()));
        files.push((path, signature));
    }
    let layout = if links.is_empty() {
        None
    } else {
        let mut encoder = CanonicalEncoder::new();
        encoder.u64(bindings.len() as u64);
        for (selected, terminal) in &bindings {
            encoder.str(selected).str(terminal);
        }
        encoder.u64(links.len() as u64);
        for link in links.values() {
            // Exact sibling targets guarantee that these names are enough:
            // neither host-local root placement nor stat generations key.
            let name = link
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("non-UTF-8 runtime alias name")?;
            let target = link
                .target
                .to_str()
                .ok_or("non-UTF-8 runtime alias target")?;
            encoder.str(name).str(target);
        }
        Some(compute(DOMAIN_RUNTIME_ALIASES, &encoder.finish()))
    };
    let (backend_files, backends) =
        codegen_backends::observe(directory, MAX_LINKS.saturating_sub(links.len()))?;
    files.extend(backend_files);
    let aliases = Aliases {
        links: links.into_values().collect(),
        layout,
        backends,
    };
    let directory_current = || {
        std::fs::symlink_metadata(directory)
            .is_ok_and(|metadata| metadata.is_dir() && FileSig::of(&metadata) == before)
    };
    if !directory_current()
        || !aliases.still_current()
        || !files.iter().all(|(path, signature)| {
            lstat_regular(path).is_ok_and(|current| current == *signature)
        })
        || !directory_current()
    {
        return Err("runtime library inputs changed during observation".into());
    }
    Ok(Observation { files, aliases })
}

#[cfg(test)]
mod tests {
    use super::super::{LiveFacts, Slot, digest_stable, probe_toolchain, tests::toolchain_fixture};
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;

    fn library_root(compiler: &Path) -> PathBuf {
        compiler.parent().unwrap().parent().unwrap().join("lib")
    }

    #[test]
    fn regular_runtime_keeps_its_bytes_but_requires_the_backend_observation_epoch() {
        let (_dir, compiler) = toolchain_fixture();
        let library = library_root(&compiler).join("libdriver.so");
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        assert!(probed.runtime_aliases.links.is_empty());
        assert_eq!(
            probed.facts.runtime_libraries,
            vec![
                digest_stable(&library).unwrap().1,
                probed.runtime_aliases.backends.layout.clone(),
            ]
        );
        assert!(probed.still_current());
    }

    #[test]
    fn sibling_soname_chains_reach_the_real_probe_and_hash_terminal_bytes() {
        let (_dir, compiler) = toolchain_fixture();
        let lib = library_root(&compiler);
        std::fs::write(lib.join("runtime-llvm"), b"LLVM runtime bytes").unwrap();
        symlink("runtime-llvm", lib.join("libLLVM.so.19")).unwrap();
        symlink("libLLVM.so.19", lib.join("libLLVM.so")).unwrap();
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        assert_eq!(probed.runtime_aliases.links.len(), 2);
        assert_eq!(probed.inputs.runtime_libraries.len(), 3);
        let llvm = digest_stable(&lib.join("runtime-llvm")).unwrap().1;
        assert_eq!(probed.facts.runtime_libraries[0], llvm);
        assert_eq!(probed.facts.runtime_libraries[1], llvm);
        assert_eq!(probed.facts.runtime_libraries.len(), 5);
        assert!(probed.still_current());
        assert_eq!(probed.facts, probe_toolchain(&compiler, &[]).unwrap().facts);
        std::fs::write(lib.join("runtime-llvm"), b"changed LLVM bytes").unwrap();
        assert!(!probed.still_current());
        assert_ne!(probed.facts, probe_toolchain(&compiler, &[]).unwrap().facts);
    }

    #[test]
    fn retargeting_equal_bytes_changes_the_canonical_alias_layout() {
        let (dir, compiler) = toolchain_fixture();
        let lib = library_root(&compiler);
        for name in ["runtime-a", "runtime-b"] {
            std::fs::write(lib.join(name), b"identical bytes").unwrap();
        }
        let alias = lib.join("libalias.so");
        symlink("runtime-a", &alias).unwrap();
        let first = probe_toolchain(&compiler, &[]).unwrap();
        std::fs::rename(&alias, dir.path().join("retained-alias")).unwrap();
        symlink("runtime-b", &alias).unwrap();
        assert!(!first.still_current());
        let changed = probe_toolchain(&compiler, &[]).unwrap();
        assert_eq!(
            first.facts.runtime_libraries[0],
            changed.facts.runtime_libraries[0]
        );
        assert_ne!(first.facts, changed.facts);
    }

    #[test]
    fn equal_layout_replacement_cannot_refresh_an_in_flight_guard() {
        let (dir, compiler) = toolchain_fixture();
        let alias = library_root(&compiler).join("libalias.so");
        symlink("libdriver.so", &alias).unwrap();
        let probed = probe_toolchain(&compiler, &[]).unwrap();
        let expected = probed.facts.clone();
        let facts = LiveFacts::new();
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
        let original = facts.toolchain_guard(&compiler, &expected).unwrap();
        std::fs::rename(&alias, dir.path().join("retained-alias")).unwrap();
        symlink("libdriver.so", &alias).unwrap();
        let refreshed = probe_toolchain(&compiler, &[]).unwrap();
        assert_eq!(refreshed.facts, expected);
        facts
            .toolchains
            .lock()
            .unwrap()
            .insert(compiler.clone(), Slot::Ready(Arc::new(refreshed)));
        facts
            .toolchain_guard(&compiler, &expected)
            .unwrap()
            .verify_unchanged(&compiler)
            .unwrap();
        assert!(original.verify_unchanged(&compiler).is_err());
    }

    #[test]
    fn dangling_escaping_directory_and_noncanonical_aliases_refuse_before_probing() {
        for target in [
            "missing",
            "/absolute/lib.so",
            "../libdriver.so",
            "./libdriver.so",
            "rustlib",
            "rustlib/test-host/lib/libcore.rlib",
            ".",
            "..",
            "libdriver.so/",
        ] {
            let (dir, compiler) = toolchain_fixture();
            symlink(target, library_root(&compiler).join("libalias.so")).unwrap();
            let log = dir.path().join("probe-log");
            let env = vec![("RABS_TEST_LOG".into(), log.to_str().unwrap().into())];
            assert!(probe_toolchain(&compiler, &env).is_err(), "{target}");
            assert!(
                !log.exists(),
                "unclosed alias reached the identity probe: {target}"
            );
        }
    }

    #[test]
    fn special_files_and_non_utf8_targets_remain_refusals() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let (_dir, compiler) = toolchain_fixture();
        let lib = library_root(&compiler);
        let _socket = std::os::unix::net::UnixListener::bind(lib.join("socket")).unwrap();
        symlink("socket", lib.join("libsocket.so")).unwrap();
        assert!(observe(&lib).is_err());
        let (_other, compiler) = toolchain_fixture();
        let lib = library_root(&compiler);
        let target = OsString::from_vec(vec![b'r', 255]);
        std::fs::write(lib.join(&target), b"unrepresentable filename").unwrap();
        symlink(&target, lib.join("libalias.so")).unwrap();
        assert!(observe(&lib).is_err());
    }

    #[test]
    fn cycles_and_depth_exhaustion_are_bounded_refusals() {
        let (_dir, compiler) = toolchain_fixture();
        let lib = library_root(&compiler);
        symlink("libb.so", lib.join("liba.so")).unwrap();
        symlink("liba.so", lib.join("libb.so")).unwrap();
        assert!(observe(&lib).unwrap_err().contains("cycle"));
        for count in [MAX_LINK_DEPTH, MAX_LINK_DEPTH + 1] {
            let (_dir, compiler) = toolchain_fixture();
            let lib = library_root(&compiler);
            for index in 0..count {
                let target = if index + 1 == count {
                    "libdriver.so".to_owned()
                } else {
                    format!("libchain-{:02}.so", index + 1)
                };
                symlink(target, lib.join(format!("libchain-{index:02}.so"))).unwrap();
            }
            assert_eq!(observe(&lib).is_ok(), count == MAX_LINK_DEPTH);
        }
    }

    #[test]
    fn shared_targets_do_not_exempt_the_link_inventory_bound() {
        for count in [MAX_LINKS, MAX_LINKS + 1] {
            let (_dir, compiler) = toolchain_fixture();
            let lib = library_root(&compiler);
            for index in 0..count {
                symlink("libdriver.so", lib.join(format!("libalias-{index:04}.so"))).unwrap();
            }
            assert_eq!(observe(&lib).is_ok(), count == MAX_LINKS);
        }
    }
}
