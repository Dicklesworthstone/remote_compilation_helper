//! Descriptor-bound disk samples, output scans, and warm-pool accounting.
//!
//! Learning metadata is bounded separately from enforcement. A large or changing
//! output tree can lose its pool fingerprint without losing the streaming charge
//! for allocations that differ from its immutable admission snapshot.

use super::{Failure, Result};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const MAX_INCREMENTAL_ENTRIES: usize = 100_000;
const MAX_WALKED_CACHE_ENTRIES: usize = 25_000;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

type Identity = (u64, u64);
type Records = BTreeMap<Identity, Signature>;
type Bindings = BTreeMap<PathBuf, Identity>;
type Aliases = BTreeMap<PathBuf, PathBuf>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Signature {
    allocated: u64,
    mode: u32,
    size: i64,
    modified_ns: i128,
    changed_ns: i128,
}

impl Signature {
    // Stat field widths differ across the supported Unix platforms.
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn of(info: &Stat) -> Result<Self> {
        let allocated = u64::try_from(info.st_blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(512))
            .ok_or_else(|| Failure::unavailable("invalid allocated output size"))?;
        Ok(Self {
            allocated,
            mode: info.st_mode as u32,
            size: info.st_size as i64,
            modified_ns: (info.st_mtime as i64 as i128) * 1_000_000_000
                + info.st_mtime_nsec as i128,
            changed_ns: (info.st_ctime as i64 as i128) * 1_000_000_000 + info.st_ctime_nsec as i128,
        })
    }
}

#[allow(clippy::unnecessary_cast)]
fn identity(info: &Stat) -> Identity {
    (info.st_dev as u64, info.st_ino as u64)
}

fn os_result<T>(result: rustix::io::Result<T>) -> Result<T> {
    result.map_err(|error| std::io::Error::from(error).into())
}

fn vanished(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP
    )
}

pub(super) fn growth_buffer(budget: u64) -> u64 {
    (budget / 16).clamp(1, 256 * 1024 * 1024)
}

fn positive(value: &Value) -> bool {
    value
        .as_u64()
        .is_some_and(|v| v > 0 && v <= i64::MAX as u64)
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn digest(value: &Value) -> bool {
    value.as_array().is_some_and(|bytes| {
        bytes.len() == 32
            && bytes
                .iter()
                .all(|byte| byte.as_u64().is_some_and(|byte| byte <= 255))
            && bytes.iter().any(|byte| byte.as_u64() != Some(0))
    })
}

pub(super) fn validate_warm_policy(policy: Option<&Value>, budget: u64) -> Result<()> {
    let Some(policy) = policy.filter(|policy| !policy.is_null()) else {
        return Ok(());
    };
    let valid = budget > 0
        && budget <= i64::MAX as u64
        && exact_keys(policy, &["cold_growth_bytes", "pools"])
        && positive(&policy["cold_growth_bytes"])
        && policy["cold_growth_bytes"]
            .as_u64()
            .is_some_and(|cold| cold > budget)
        && policy["pools"].as_array().is_some_and(|pools| {
            pools.len() == 8
                && pools.iter().any(|pool| !pool.is_null())
                && pools.iter().all(|pool| {
                    pool.is_null()
                        || (exact_keys(pool, &["identity", "state", "retained_bytes"])
                            && digest(&pool["identity"])
                            && digest(&pool["state"])
                            && positive(&pool["retained_bytes"]))
                })
        });
    if !valid {
        return Err(Failure::unavailable("invalid warm disk policy"));
    }
    let mut identities = BTreeSet::new();
    for pool in policy["pools"].as_array().expect("validated pools") {
        if !pool.is_null() {
            let bytes: Vec<u64> = pool["identity"]
                .as_array()
                .expect("validated identity")
                .iter()
                .map(|byte| byte.as_u64().expect("validated byte"))
                .collect();
            if !identities.insert(bytes) {
                return Err(Failure::unavailable("duplicate warm disk pool identity"));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_cargo_cache_plan(plan: Option<&Value>, required: bool) -> Result<()> {
    let plan = plan.filter(|plan| !plan.is_null());
    if plan.is_none() && !required {
        return Ok(());
    }
    let valid = plan.is_some_and(|plan| {
        exact_keys(plan, &["name", "additional_home", "verified"])
            && plan["verified"].is_boolean()
            && plan["name"].as_str().is_some_and(|name| {
                name.starts_with("rch-cargo-cache-")
                    && name.len() > 16
                    && name.len() <= 255
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
            && (plan["additional_home"].is_null()
                || plan["additional_home"]
                    .as_str()
                    .is_some_and(|home| Path::new(home).is_absolute() && !home.contains('\0')))
    });
    if !valid {
        return Err(Failure::unavailable(
            "missing or invalid original-command Cargo cache scope",
        ));
    }
    if plan.expect("validated plan")["verified"] != Value::Bool(true) {
        return Err(Failure::unavailable(
            "Cargo cache scope is unresolved; use a literal absolute CARGO_HOME and supported env prefix",
        ));
    }
    Ok(())
}

fn output_bindings(paths: &[PathBuf]) -> Result<Bindings> {
    let mut bindings = BTreeMap::new();
    for path in paths {
        let info = os_result(rustix::fs::statat(
            rustix::fs::CWD,
            path,
            AtFlags::SYMLINK_NOFOLLOW,
        ))?;
        if FileType::from_raw_mode(info.st_mode) != FileType::Directory {
            return Err(Failure::unavailable(
                "output root is not a physical directory",
            ));
        }
        bindings.insert(path.clone(), identity(&info));
    }
    Ok(bindings)
}

fn verify_output_bindings(bindings: &Bindings) -> Result<()> {
    if output_bindings(&bindings.keys().cloned().collect::<Vec<_>>())? != *bindings {
        return Err(Failure::unavailable("output root changed during execution"));
    }
    Ok(())
}

/// Resolve known cache redirects even when their final directory is absent.
/// Unlike create_dir_all, this never seeds missing ancestor trees.
fn resolve_cache_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Failure::unavailable("Cargo cache path is not absolute"));
    }
    enum Step {
        Component(OsString),
        ResolvedLink(PathBuf),
    }
    let mut pending: VecDeque<Step> = path
        .components()
        .map(|component| Step::Component(component.as_os_str().to_owned()))
        .collect();
    let mut resolved = PathBuf::new();
    let mut resolving = BTreeSet::new();
    while let Some(step) = pending.pop_front() {
        let component = match step {
            Step::Component(component) => component,
            Step::ResolvedLink(path) => {
                resolving.remove(&path);
                continue;
            }
        };
        match Path::new(&component).components().next() {
            Some(Component::RootDir) => resolved = PathBuf::from("/"),
            Some(Component::CurDir) | None => {}
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            Some(Component::Normal(_)) => {
                resolved.push(&component);
                match fs::symlink_metadata(&resolved) {
                    Ok(info) if info.file_type().is_symlink() => {
                        if !resolving.insert(resolved.clone()) {
                            return Err(Failure::unavailable("Cargo cache redirect loop"));
                        }
                        let destination = fs::read_link(&resolved)?;
                        pending.push_front(Step::ResolvedLink(resolved.clone()));
                        resolved.pop();
                        for part in destination.components().rev() {
                            pending.push_front(Step::Component(part.as_os_str().to_owned()));
                        }
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Some(Component::Prefix(_)) => unreachable!("Unix paths have no prefix"),
        }
    }
    Ok(resolved)
}

fn prepare_cargo_cache_roots(
    plan: Option<&Value>,
    base: Option<&OsStr>,
) -> Result<(Vec<PathBuf>, Aliases)> {
    let Some(plan) = plan.filter(|plan| !plan.is_null()) else {
        return Ok((Vec::new(), BTreeMap::new()));
    };
    validate_cargo_cache_plan(Some(plan), false)?;
    let base = Path::new(base.unwrap_or_else(|| OsStr::new("")));
    if !base.is_absolute()
        || !fs::canonicalize(base).is_ok_and(|resolved| resolved.as_os_str() == base.as_os_str())
        || !base.is_dir()
    {
        return Err(Failure::unavailable(
            "worker Cargo cache base is not a resolved physical directory",
        ));
    }
    let mut homes = vec![base.join(plan["name"].as_str().expect("validated cache name"))];
    if let Some(additional) = plan["additional_home"].as_str() {
        push_unique(&mut homes, PathBuf::from(additional));
    }
    let mut roots = Vec::new();
    let mut aliases = BTreeMap::new();
    for home in homes {
        for logical in [home.clone(), home.join("registry"), home.join("git")] {
            let physical = resolve_cache_path(&logical)?;
            if !physical.parent().is_some_and(Path::is_dir) {
                return Err(Failure::unavailable(
                    "Cargo cache parent must already exist before admission",
                ));
            }
            match fs::create_dir(&physical) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            if !fs::symlink_metadata(&physical)?.file_type().is_dir() {
                return Err(Failure::unavailable(
                    "Cargo cache output root is not a physical directory",
                ));
            }
            push_unique(&mut roots, physical.clone());
            aliases.insert(logical, physical);
        }
    }
    verify_cargo_cache_bindings(&aliases)?;
    Ok((roots, aliases))
}

fn verify_cargo_cache_bindings(aliases: &Aliases) -> Result<()> {
    for (logical, physical) in aliases {
        if resolve_cache_path(logical)? != *physical {
            return Err(Failure::unavailable(
                "Cargo cache redirect changed during execution",
            ));
        }
    }
    Ok(())
}

fn cache_walk_is_bounded(roots: &[PathBuf], limit: usize) -> Result<bool> {
    let mut entries = 0usize;
    let mut visited = BTreeSet::new();
    let mut pending = roots.to_vec();
    while let Some(path) = pending.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        let listing = match fs::read_dir(&path) {
            Ok(listing) => listing,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        for entry in listing {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            entries += 1;
            if entries > limit {
                return Ok(false);
            }
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(entry.path()),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(true)
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

fn filesystem_sample(paths: &[PathBuf]) -> Result<BTreeMap<u64, u64>> {
    let mut samples = BTreeMap::<u64, u64>::new();
    for path in paths {
        // One open directory binds the device and unprivileged available blocks.
        // Probes may be symlinks; managed output roots are checked separately.
        let descriptor = os_result(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ))?;
        let device = identity(&os_result(rustix::fs::fstat(&descriptor))?).0;
        let info = os_result(rustix::fs::fstatvfs(&descriptor))?;
        #[allow(clippy::unnecessary_cast)]
        let available = (info.f_bavail as u64)
            .checked_mul(info.f_frsize as u64)
            .ok_or_else(|| Failure::unavailable("invalid available filesystem size"))?;
        samples
            .entry(device)
            .and_modify(|value| *value = (*value).min(available))
            .or_insert(available);
    }
    Ok(samples)
}

/// Decode Unix names with the same surrogate-escape representation used by the
/// original pool protocol. Invalid UTF-8 bytes remain distinct in its digest.
fn path_codepoints(mut bytes: &[u8]) -> Vec<u32> {
    let mut points = Vec::with_capacity(bytes.len());
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                points.extend(text.chars().map(u32::from));
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                points.extend(
                    std::str::from_utf8(&bytes[..valid])
                        .expect("validated UTF-8 prefix")
                        .chars()
                        .map(u32::from),
                );
                let invalid = error.error_len().unwrap_or(bytes.len() - valid);
                points.extend(
                    bytes[valid..valid + invalid]
                        .iter()
                        .map(|byte| 0xdc00 + u32::from(*byte)),
                );
                bytes = &bytes[valid + invalid..];
            }
        }
    }
    points
}

fn ascii_json_string(points: &[u32], output: &mut String) {
    output.push('"');
    for &point in points {
        match point {
            0x22 => output.push_str("\\\""),
            0x5c => output.push_str("\\\\"),
            0x08 => output.push_str("\\b"),
            0x0c => output.push_str("\\f"),
            0x0a => output.push_str("\\n"),
            0x0d => output.push_str("\\r"),
            0x09 => output.push_str("\\t"),
            0x20..=0x7e => output.push(char::from_u32(point).expect("ASCII code point")),
            0..=0xffff => write!(output, "\\u{point:04x}").expect("writing a String"),
            _ => {
                let point = point - 0x10000;
                write!(
                    output,
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (point >> 10),
                    0xdc00 + (point & 1023)
                )
                .expect("writing a String");
            }
        }
    }
    output.push('"');
}

fn absolute_pool_name(target: &Path) -> Vec<u32> {
    // The input is absolute. Normalize '.' and '..' without resolving symlinks,
    // matching the identity protocol's abspath rather than canonicalize.
    let raw = target.as_os_str().as_bytes();
    let double_root = raw.starts_with(b"//") && !raw.starts_with(b"///");
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in raw.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    let mut name = if double_root {
        b"//".to_vec()
    } else {
        b"/".to_vec()
    };
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            name.push(b'/');
        }
        name.extend_from_slice(part);
    }
    path_codepoints(&name)
}

fn pool_identity(target: &Path, boot: &str, binding: Identity) -> [u8; 32] {
    let mut input = String::from("[\"rch-pool-identity-v1\",");
    ascii_json_string(&absolute_pool_name(target), &mut input);
    input.push(',');
    ascii_json_string(&boot.chars().map(u32::from).collect::<Vec<_>>(), &mut input);
    write!(input, ",{},{}]", binding.0, binding.1).expect("writing a String");
    Sha256::digest(input.as_bytes()).into()
}

struct PoolEntry {
    relative: Vec<u32>,
    identity: Identity,
    signature: Signature,
}

fn pool_fingerprint(mut entries: Vec<PoolEntry>) -> [u8; 32] {
    entries.sort_unstable_by(|left, right| left.relative.cmp(&right.relative));
    let mut digest = Sha256::new();
    digest.update(b"rch-pool-state-v1\0");
    let mut encoded = String::new();
    for entry in entries {
        encoded.clear();
        encoded.push('[');
        ascii_json_string(&entry.relative, &mut encoded);
        writeln!(
            encoded,
            ",{},{},{},{},{},{},{}]",
            entry.identity.0,
            entry.identity.1,
            entry.signature.allocated,
            entry.signature.mode,
            entry.signature.size,
            entry.signature.modified_ns,
            entry.signature.changed_ns,
        )
        .expect("writing a String");
        digest.update(encoded.as_bytes());
    }
    digest.finalize().into()
}

#[derive(Clone, Debug)]
pub(super) struct OutputScan {
    total: u64,
    records: Option<Arc<Records>>,
    pool_state: Option<[u8; 32]>,
    pool_bytes: u64,
    added: Option<u64>,
}

struct DirectoryScan {
    file: File,
    entries: Dir,
    signature: Signature,
    relative: Option<Vec<u32>>,
}

struct Walker<'a> {
    total: u64,
    added: Option<u64>,
    pool_bytes: u64,
    seen: BTreeSet<Identity>,
    devices: BTreeSet<u64>,
    baseline: Option<&'a Records>,
    records: Option<Records>,
    pool_entries: Option<Vec<PoolEntry>>,
    limit: usize,
}

impl Walker<'_> {
    fn incomplete(&mut self) {
        self.records = None;
        self.pool_entries = None;
    }

    fn enter(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &OsStr,
        relative: Option<Vec<u32>>,
        observe_directory: &mut impl FnMut(),
    ) -> Result<Option<DirectoryScan>> {
        let info = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => info,
            Err(error) if vanished(error) => {
                self.incomplete();
                return Ok(None);
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let identity = identity(&info);
        let signature = Signature::of(&info)?;
        if let (Some(relative), Some(entries)) = (&relative, &mut self.pool_entries) {
            if entries.len() >= self.limit {
                self.incomplete();
            } else {
                entries.push(PoolEntry {
                    relative: relative.clone(),
                    identity,
                    signature: signature.clone(),
                });
            }
        }
        if self.seen.contains(&identity) {
            return Ok(None);
        }
        if !self.devices.contains(&identity.0) {
            return Err(Failure::unavailable(
                "unmonitored filesystem inside output root",
            ));
        }
        self.seen.insert(identity);
        self.total = self
            .total
            .checked_add(signature.allocated)
            .ok_or_else(|| Failure::unavailable("output allocation counter overflow"))?;
        if let (Some(added), Some(baseline)) = (&mut self.added, self.baseline)
            && baseline.get(&identity) != Some(&signature)
        {
            *added = added
                .checked_add(signature.allocated)
                .ok_or_else(|| Failure::unavailable("output growth counter overflow"))?;
        }
        if relative.is_some() {
            self.pool_bytes = self
                .pool_bytes
                .checked_add(signature.allocated)
                .ok_or_else(|| Failure::unavailable("pool allocation counter overflow"))?;
        }
        if let Some(records) = &mut self.records {
            if records.len() >= self.limit {
                self.incomplete();
            } else {
                records.insert(identity, signature.clone());
            }
        }
        if FileType::from_raw_mode(info.st_mode) != FileType::Directory {
            return Ok(None);
        }
        let descriptor = match rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(error) if vanished(error) => {
                self.incomplete();
                return Ok(None);
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        let file = File::from(descriptor);
        let current = os_result(rustix::fs::fstat(&file))?;
        if self::identity(&current) != identity {
            return Err(Failure::unavailable("output directory changed during scan"));
        }
        if Signature::of(&current)? != signature {
            self.incomplete();
        }
        observe_directory();
        let entries = match Dir::read_from(&file) {
            Ok(entries) => entries,
            Err(error) if vanished(error) => {
                self.incomplete();
                return Ok(None);
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        Ok(Some(DirectoryScan {
            file,
            entries,
            signature,
            relative,
        }))
    }
}

fn measure_outputs(
    paths: &[PathBuf],
    target: &Path,
    baseline: Option<&Records>,
    limit: usize,
    mut observe_directory: impl FnMut(),
) -> Result<OutputScan> {
    let devices = output_bindings(paths)?
        .values()
        .map(|identity| identity.0)
        .collect();
    let mut walker = Walker {
        total: 0,
        added: baseline.map(|_| 0),
        pool_bytes: 0,
        seen: BTreeSet::new(),
        devices,
        baseline,
        records: Some(BTreeMap::new()),
        pool_entries: Some(Vec::new()),
        limit,
    };
    let mut ordered = vec![target.to_owned()];
    for path in paths {
        push_unique(&mut ordered, path.clone());
    }
    for path in ordered {
        let relative = (path == target).then(|| vec![u32::from('.')]);
        let first = walker.enter(
            rustix::fs::CWD,
            path.as_os_str(),
            relative,
            &mut observe_directory,
        )?;
        let mut pending: Vec<DirectoryScan> = first.into_iter().collect();
        while let Some(directory) = pending.last_mut() {
            match directory.entries.next() {
                Some(Ok(entry)) => {
                    let name = entry.file_name().to_bytes();
                    if matches!(name, b"." | b"..") {
                        continue;
                    }
                    let relative = directory.relative.as_ref().map(|parent| {
                        let mut child = parent.clone();
                        child.push(u32::from('/'));
                        child.extend(path_codepoints(name));
                        child
                    });
                    if let Some(child) = walker.enter(
                        directory.file.as_fd(),
                        OsStr::from_bytes(name),
                        relative,
                        &mut observe_directory,
                    )? {
                        pending.push(child);
                    }
                }
                Some(Err(error)) if vanished(error) => {
                    walker.incomplete();
                    pending.pop();
                }
                Some(Err(error)) => return Err(std::io::Error::from(error).into()),
                None => {
                    let finished = pending.pop().expect("active directory");
                    if Signature::of(&os_result(rustix::fs::fstat(&finished.file))?)?
                        != finished.signature
                    {
                        walker.incomplete();
                    }
                }
            }
        }
    }
    Ok(OutputScan {
        total: walker.total,
        records: walker.records.map(Arc::new),
        pool_state: walker.pool_entries.map(pool_fingerprint),
        pool_bytes: walker.pool_bytes,
        added: walker.added,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Pool {
    identity: [u8; 32],
    state: [u8; 32],
    retained_bytes: u64,
}

pub(super) struct Scanner {
    target: PathBuf,
    paths: Vec<PathBuf>,
    outputs: Vec<PathBuf>,
    bindings: Bindings,
    cargo_aliases: Aliases,
    pool_identity: [u8; 32],
    initial: OutputScan,
    pub(super) devices: BTreeSet<u64>,
}

impl Scanner {
    pub(super) fn new(
        target: &Path,
        probes: &[PathBuf],
        outputs: &[PathBuf],
        cargo: Option<&Value>,
        boot: &str,
    ) -> Result<Self> {
        Self::with_limits(
            target,
            probes,
            outputs,
            cargo,
            boot,
            std::env::var_os("RCH_CH_BASE").as_deref(),
            MAX_WALKED_CACHE_ENTRIES,
            MAX_INCREMENTAL_ENTRIES,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_limits(
        target: &Path,
        probes: &[PathBuf],
        outputs: &[PathBuf],
        cargo: Option<&Value>,
        boot: &str,
        cargo_base: Option<&OsStr>,
        cache_limit: usize,
        record_limit: usize,
    ) -> Result<Self> {
        let (cache_outputs, cargo_aliases) = prepare_cargo_cache_roots(cargo, cargo_base)?;
        let mut selected_outputs = vec![target.to_owned()];
        for path in outputs {
            push_unique(&mut selected_outputs, path.clone());
        }
        if cache_walk_is_bounded(&cache_outputs, cache_limit)? {
            for path in &cache_outputs {
                push_unique(&mut selected_outputs, path.clone());
            }
        }
        let mut paths = probes.to_vec();
        for path in selected_outputs.iter().chain(&cache_outputs) {
            push_unique(&mut paths, path.clone());
        }
        let bindings = output_bindings(&selected_outputs)?;
        let pool_identity = pool_identity(target, boot, bindings[target]);
        let mut scanner = Self {
            target: target.to_owned(),
            paths,
            outputs: selected_outputs,
            bindings,
            cargo_aliases,
            pool_identity,
            initial: OutputScan {
                total: 0,
                records: None,
                pool_state: None,
                pool_bytes: 0,
                added: None,
            },
            devices: BTreeSet::new(),
        };
        scanner.devices = scanner.sample()?.0.into_keys().collect();
        scanner.verify_bindings()?;
        scanner.initial = measure_outputs(&scanner.outputs, target, None, record_limit, || {})?;
        scanner.verify_bindings()?;
        Ok(scanner)
    }

    fn verify_bindings(&self) -> Result<()> {
        verify_cargo_cache_bindings(&self.cargo_aliases)?;
        verify_output_bindings(&self.bindings)
    }

    pub(super) fn sample(&self) -> Result<(BTreeMap<u64, u64>, Instant)> {
        self.verify_bindings()?;
        let samples = filesystem_sample(&self.paths)?;
        // Timestamp receipt, before post-probe validation or supervisor delay.
        let sampled_at = Instant::now();
        verify_output_bindings(&self.bindings)?;
        verify_cargo_cache_bindings(&self.cargo_aliases)?;
        Ok((samples, sampled_at))
    }

    pub(super) fn scan(&self) -> Result<OutputScan> {
        self.verify_bindings()?;
        let result = measure_outputs(
            &self.outputs,
            &self.target,
            self.initial.records.as_deref(),
            MAX_INCREMENTAL_ENTRIES,
            || {},
        )?;
        verify_output_bindings(&self.bindings)?;
        verify_cargo_cache_bindings(&self.cargo_aliases)?;
        Ok(result)
    }

    pub(super) fn baseline_output_bytes(&self) -> u64 {
        self.initial.total
    }
}

pub(super) struct Accounting {
    budget: u64,
    floor: u64,
    devices: BTreeSet<u64>,
    baseline: u64,
    baseline_records: Option<Arc<Records>>,
    pool_identity: [u8; 32],
    baseline_pool: Option<Pool>,
    final_pool: Option<Pool>,
    admitted_pool: Option<Pool>,
    incremental_reliable: bool,
    strict_tracking: bool,
    peak_added: u64,
    unproven_baseline: u64,
    pub(super) peak_output: u64,
    pub(super) peak_growth: u64,
    free: BTreeMap<u64, u64>,
    free_start: BTreeMap<u64, u64>,
    free_min: BTreeMap<u64, u64>,
    floors: BTreeMap<u64, u64>,
    previous: Option<(Instant, BTreeMap<u64, u64>)>,
}

impl Accounting {
    pub(super) fn new(
        budget: u64,
        floor: u64,
        scanner: &Scanner,
        warm: Option<&Value>,
        strict: bool,
    ) -> Result<Self> {
        let baseline_pool = scanner.initial.pool_state.map(|state| Pool {
            identity: scanner.pool_identity,
            state,
            retained_bytes: scanner.initial.pool_bytes,
        });
        let mut accounting = Self {
            budget,
            floor,
            devices: scanner.devices.clone(),
            baseline: scanner.initial.total,
            baseline_records: scanner.initial.records.clone(),
            pool_identity: scanner.pool_identity,
            final_pool: baseline_pool.clone(),
            admitted_pool: None,
            incremental_reliable: scanner.initial.records.is_some() && baseline_pool.is_some(),
            baseline_pool,
            strict_tracking: false,
            peak_added: 0,
            unproven_baseline: 0,
            peak_output: scanner.initial.total,
            peak_growth: 0,
            free: BTreeMap::new(),
            free_start: BTreeMap::new(),
            free_min: BTreeMap::new(),
            floors: scanner
                .devices
                .iter()
                .map(|device| (*device, floor))
                .collect(),
            previous: None,
        };
        accounting.require_warm_pool(warm)?;
        if strict && scanner.initial.records.is_none() {
            return Err(Failure::unavailable(
                "bounded initial output tracking is unavailable",
            ));
        }
        accounting.strict_tracking |= strict;
        Ok(accounting)
    }

    fn require_warm_pool(&mut self, policy: Option<&Value>) -> Result<()> {
        validate_warm_policy(policy, self.budget)?;
        let Some(policy) = policy.filter(|policy| !policy.is_null()) else {
            return Ok(());
        };
        let pool = self.baseline_pool.as_ref();
        if pool.is_none()
            || !policy["pools"]
                .as_array()
                .expect("validated pools")
                .contains(&json!(pool))
        {
            let mut failure = Failure::new(
                "cold_required",
                0,
                0,
                "retained output pool no longer matches its warm reservation",
            );
            failure.required_growth_bytes = policy["cold_growth_bytes"].as_u64();
            return Err(failure);
        }
        let unproven = self
            .baseline
            .saturating_sub(pool.expect("matched pool").retained_bytes);
        if unproven.saturating_add(growth_buffer(self.budget)) >= self.budget {
            let mut failure = Failure::new(
                "cold_required",
                0,
                0,
                format!(
                    "unproven output baseline ({unproven} bytes) leaves insufficient warm growth allowance"
                ),
            );
            failure.required_growth_bytes = policy["cold_growth_bytes"].as_u64();
            return Err(failure);
        }
        self.unproven_baseline = unproven;
        self.strict_tracking = true;
        self.peak_growth = self.peak_growth.max(unproven);
        self.admitted_pool = self.baseline_pool.clone();
        Ok(())
    }

    pub(super) fn admit(
        &mut self,
        free: BTreeMap<u64, u64>,
        floors: BTreeMap<u64, u64>,
        sampled_at: Instant,
    ) {
        self.free = free.clone();
        self.free_start = free.clone();
        self.free_min = free.clone();
        self.floors = floors;
        self.previous = Some((sampled_at, free));
    }

    pub(super) fn observe_free(&mut self, samples: BTreeMap<u64, u64>, at: Instant) -> Result<()> {
        if samples.keys().copied().collect::<BTreeSet<_>>() != self.devices {
            return Err(Failure::unavailable(
                "monitored filesystem identity changed",
            ));
        }
        for (&device, &free) in &samples {
            self.free_min
                .entry(device)
                .and_modify(|value| *value = (*value).min(free))
                .or_insert(free);
            let base = growth_buffer(self.budget);
            let margin = if let Some((previous_time, previous)) = &self.previous {
                let elapsed = at
                    .saturating_duration_since(*previous_time)
                    .as_secs_f64()
                    .max(0.001);
                let rate = previous[&device].saturating_sub(free) as f64 / elapsed;
                base.max((rate * 2.0) as u64)
            } else {
                base
            };
            if free <= self.floors[&device].saturating_add(margin) {
                return Err(Failure::new(
                    "free_floor",
                    free,
                    self.peak_growth,
                    "protected floor or observed write-rate buffer reached",
                ));
            }
        }
        self.free = samples.clone();
        self.previous = Some((at, samples));
        Ok(())
    }

    pub(super) fn observe_output(&mut self, scan: OutputScan) -> Result<()> {
        self.peak_output = self.peak_output.max(scan.total);
        let net_growth = scan.total.saturating_sub(self.baseline);
        self.final_pool = scan.pool_state.map(|state| Pool {
            identity: self.pool_identity,
            state,
            retained_bytes: scan.pool_bytes,
        });
        if scan.records.is_none() || self.final_pool.is_none() {
            self.incremental_reliable = false;
        }
        let mut added = scan.added;
        if added.is_none()
            && let (Some(baseline), Some(records)) = (&self.baseline_records, &scan.records)
        {
            added = Some(
                records
                    .iter()
                    .filter(|(identity, signature)| baseline.get(*identity) != Some(*signature))
                    .try_fold(0u64, |sum, (_, signature)| {
                        sum.checked_add(signature.allocated)
                    })
                    .ok_or_else(|| Failure::unavailable("output growth counter overflow"))?,
            );
        }
        if added.is_none() && self.strict_tracking {
            self.incremental_reliable = false;
            added = Some(scan.total);
        }
        if let Some(added) = added {
            self.peak_added = self.peak_added.max(added);
        }
        self.peak_growth = self.peak_growth.max(
            self.unproven_baseline
                .saturating_add(net_growth.max(self.peak_added)),
        );
        if self.peak_growth > self.budget {
            return Err(Failure::new(
                "growth",
                self.free.values().copied().min().unwrap_or(0),
                self.peak_growth,
                "allocated build output exceeded its reservation",
            ));
        }
        Ok(())
    }

    pub(super) fn usage(&self, complete: bool, exit_code: Option<i32>) -> Value {
        let incremental = self.incremental_reliable.then(|| {
            json!({
                "version": 1,
                "baseline_output_bytes": self.baseline,
                "peak_added_output_bytes": self.peak_added,
                "peak_free_drop_bytes": self.free_start.iter().fold(0u64, |sum, (device, start)| {
                    sum.saturating_add(start.saturating_sub(self.free_min[device]))
                }),
                "baseline_pool": self.baseline_pool,
                "final_pool": self.final_pool,
            })
        });
        json!({
            "max_growth_bytes": self.budget, "min_free_bytes": self.floor,
            "peak_output_bytes": self.peak_output, "peak_growth_bytes": self.peak_growth,
            "incremental": incremental, "admitted_pool": self.admitted_pool,
            "complete": complete, "exit_code": exit_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    fn tree() -> (TempDir, PathBuf) {
        let temporary = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = tempfile::tempdir_in(temporary).unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        (root, target)
    }

    fn write_output(path: &Path, bytes: usize) -> u64 {
        fs::write(path, vec![0x5a; bytes]).unwrap();
        fs::metadata(path).unwrap().blocks() * 512
    }

    fn scanner(target: &Path, outputs: &[PathBuf]) -> Scanner {
        Scanner::new(target, &[target.to_owned()], outputs, None, "test-boot").unwrap()
    }

    fn policy(accounting: &Accounting) -> Value {
        let mut pools = vec![json!(accounting.baseline_pool)];
        pools.resize(8, Value::Null);
        json!({"cold_growth_bytes": accounting.budget * 2, "pools": pools})
    }

    fn cache_plan(additional: Option<&Path>) -> Value {
        json!({"name": "rch-cargo-cache-worker", "additional_home": additional, "verified": true})
    }

    fn cache_roots(root: &Path) -> (PathBuf, Value, Vec<PathBuf>, Aliases) {
        let base = root.join("worker cache base");
        fs::create_dir(&base).unwrap();
        let plan = cache_plan(None);
        let (roots, aliases) =
            prepare_cargo_cache_roots(Some(&plan), Some(base.as_os_str())).unwrap();
        (base, plan, roots, aliases)
    }

    fn cold_failure(result: Result<()>, required: u64) {
        let failure = result.unwrap_err();
        assert_eq!(failure.reason, "cold_required");
        assert_eq!(failure.required_growth_bytes, Some(required));
        assert_eq!(failure.growth, 0);
    }

    #[test]
    fn pool_encoding_preserves_ascii_protocol_unicode_and_invalid_name_bytes() {
        let mut encoded = String::new();
        ascii_json_string(
            &path_codepoints(b"a\"\\\n\x7f\xc3\xa9\xf0\x9f\xa6\x80\xff"),
            &mut encoded,
        );
        assert_eq!(
            encoded,
            "\"a\\\"\\\\\\n\\u007f\\u00e9\\ud83e\\udd80\\udcff\""
        );
        let signature = Signature {
            allocated: 4096,
            mode: 33188,
            size: 17,
            modified_ns: -1,
            changed_ns: 1234567890123456789,
        };
        let entries = vec![
            PoolEntry {
                relative: path_codepoints(b"./\xff"),
                identity: (7, 22),
                signature: signature.clone(),
            },
            PoolEntry {
                relative: path_codepoints("./é🦀".as_bytes()),
                identity: (7, 21),
                signature,
            },
        ];
        let expected = Sha256::digest(b"rch-pool-state-v1\0[\"./\\u00e9\\ud83e\\udd80\",7,21,4096,33188,17,-1,1234567890123456789]\n[\"./\\udcff\",7,22,4096,33188,17,-1,1234567890123456789]\n");
        assert_eq!(pool_fingerprint(entries), <[u8; 32]>::from(expected));
        let target = Path::new("/tmp/a/../é🦀");
        let expected = Sha256::digest(
            b"[\"rch-pool-identity-v1\",\"/tmp/\\u00e9\\ud83e\\udd80\",\"test-boot\",7,21]",
        );
        assert_eq!(
            pool_identity(target, "test-boot", (7, 21)),
            <[u8; 32]>::from(expected)
        );
    }

    #[test]
    fn nested_roots_and_hardlinks_keep_target_first_pool_credit() {
        let (root, target) = tree();
        let nested = target.join("nested");
        let source = root.path().join("source");
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&source).unwrap();
        let bytes = write_output(&nested.join("artifact"), 64 * 1024);
        fs::hard_link(nested.join("artifact"), target.join("alias")).unwrap();
        fs::hard_link(nested.join("artifact"), source.join("alias")).unwrap();
        let target_only = measure_outputs(&[target.clone()], &target, None, 100, || {}).unwrap();
        let forward = measure_outputs(
            &[source.clone(), nested.clone(), target.clone()],
            &target,
            None,
            100,
            || {},
        )
        .unwrap();
        let reverse = measure_outputs(
            &[target.clone(), nested, source.clone()],
            &target,
            None,
            100,
            || {},
        )
        .unwrap();
        assert_eq!(
            forward.total,
            target_only.total + fs::metadata(&source).unwrap().blocks() * 512
        );
        assert_eq!(forward.pool_bytes, target_only.total);
        assert_eq!(forward.pool_state, target_only.pool_state);
        assert_eq!(forward.pool_state, reverse.pool_state);
        assert!(target_only.total >= bytes);
        assert_eq!(target_only.records.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn scan_never_follows_arbitrary_symlinks_and_accepts_non_utf8_names() {
        let (root, target) = tree();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let outside_bytes = write_output(&outside.join("artifact"), 128 * 1024);
        symlink(&outside, target.join("redirect")).unwrap();
        let invalid_name = target.join(OsString::from_vec(b"artifact-\xff".to_vec()));
        let inside_bytes = write_output(&invalid_name, 4096);
        let value = scanner(&target, &[]);
        let scan = value.scan().unwrap();
        assert!(scan.total >= inside_bytes);
        assert!(scan.total < outside_bytes);
        assert!(scan.pool_state.is_some());
        assert_eq!(scan.records.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn output_symlinks_and_replaced_roots_refuse_sampling_and_scanning() {
        let (root, target) = tree();
        let alias = root.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert!(Scanner::new(&alias, &[alias.clone()], &[], None, "boot").is_err());
        let value = scanner(&target, &[]);
        fs::rename(&target, root.path().join("retained-target")).unwrap();
        fs::create_dir(&target).unwrap();
        assert_eq!(value.sample().unwrap_err().reason, "monitor_unavailable");
        assert_eq!(value.scan().unwrap_err().reason, "monitor_unavailable");
    }

    #[test]
    fn reused_inode_and_cleanup_cannot_erase_new_allocation_charge() {
        let (root, target) = tree();
        let retained = target.join("retained");
        write_output(&retained, 128 * 1024);
        let value = scanner(&target, &[]);
        let inode = fs::metadata(&retained).unwrap().ino();
        let rewritten = write_output(&retained, 128 * 1024);
        File::open(&retained)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(123)),
            )
            .unwrap();
        assert_eq!(fs::metadata(&retained).unwrap().ino(), inode);
        let rewritten_scan = value.scan().unwrap();
        assert!(rewritten_scan.added.unwrap() >= rewritten);
        assert_ne!(rewritten_scan.pool_state, value.initial.pool_state);

        fs::rename(&retained, root.path().join("retained-outside")).unwrap();
        let added = write_output(&target.join("new"), 64 * 1024);
        let scan = value.scan().unwrap();
        assert!(scan.total < value.initial.total);
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        accounting.observe_output(scan).unwrap();
        assert!(accounting.peak_growth >= added);
    }

    #[test]
    fn bounded_learning_preserves_streamed_growth_and_hardlink_deduplication() {
        let (root, target) = tree();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let retained = target.join("retained");
        write_output(&retained, 128 * 1024);
        let value = scanner(&target, &[source.clone()]);
        fs::rename(&retained, root.path().join("retained-outside")).unwrap();
        let added = write_output(&target.join("new"), 64 * 1024);
        fs::hard_link(target.join("new"), source.join("new-alias")).unwrap();
        let scan = measure_outputs(
            &value.outputs,
            &target,
            value.initial.records.as_deref(),
            1,
            || {},
        )
        .unwrap();
        assert!(scan.records.is_none());
        assert!(scan.pool_state.is_none());
        assert!(scan.total < value.initial.total);
        assert!(scan.added.unwrap() >= added);
        assert!(scan.added.unwrap() < added * 2);
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        let warm = policy(&accounting);
        accounting.require_warm_pool(Some(&warm)).unwrap();
        accounting.observe_output(scan).unwrap();
        let usage = accounting.usage(true, Some(0));
        assert_eq!(usage["admitted_pool"], warm["pools"][0]);
        assert_eq!(usage["incremental"], Value::Null);
        assert_eq!(usage["complete"], true);
        assert!(accounting.peak_growth >= added);
    }

    #[test]
    fn directory_churn_discards_proof_without_discarding_streamed_additions() {
        let (_root, target) = tree();
        write_output(&target.join("retained"), 128 * 1024);
        let value = scanner(&target, &[]);
        let added = write_output(&target.join("new"), 64 * 1024);
        let mut observed = false;
        let scan = measure_outputs(
            &value.outputs,
            &target,
            value.initial.records.as_deref(),
            100,
            || {
                if !observed {
                    observed = true;
                    fs::write(target.join("concurrent"), b"").unwrap();
                    File::open(&target)
                        .unwrap()
                        .set_times(
                            fs::FileTimes::new()
                                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(123)),
                        )
                        .unwrap();
                }
            },
        )
        .unwrap();
        assert!(scan.records.is_none());
        assert!(scan.pool_state.is_none());
        assert!(scan.added.unwrap() >= added);
    }

    #[test]
    fn strict_source_tracking_refuses_incomplete_baseline_and_caps_do_not_hide_growth() {
        let (root, target) = tree();
        let retained = target.join("retained");
        write_output(&retained, 128 * 1024);
        let incomplete = Scanner::with_limits(
            &target,
            &[target.clone()],
            &[],
            None,
            "boot",
            None,
            25_000,
            1,
        )
        .unwrap();
        let failure = Accounting::new(MIB, 0, &incomplete, None, true)
            .err()
            .unwrap();
        assert!(failure.detail.contains("initial output tracking"));
        assert!(Accounting::new(MIB, 0, &incomplete, None, false).is_ok());

        let value = scanner(&target, &[]);
        let warm = policy(&Accounting::new(MIB, 0, &value, None, false).unwrap());
        let failure = Accounting::new(MIB, 0, &incomplete, Some(&warm), true)
            .err()
            .unwrap();
        assert_eq!(failure.reason, "cold_required");
        assert_eq!(failure.required_growth_bytes, Some(2 * MIB));
        let mut accounting = Accounting::new(16 * 1024, 0, &value, None, true).unwrap();
        fs::rename(&retained, root.path().join("retained-outside")).unwrap();
        let added = write_output(&target.join("incoming"), 64 * 1024);
        let scan = measure_outputs(
            &value.outputs,
            &target,
            value.initial.records.as_deref(),
            1,
            || {},
        )
        .unwrap();
        assert!(scan.total < value.initial.total);
        let failure = accounting.observe_output(scan).unwrap_err();
        assert_eq!(failure.reason, "growth");
        assert!(failure.growth >= added);
        assert!(accounting.admitted_pool.is_none());
    }

    #[test]
    fn unknown_warm_attribution_charges_total_and_preserves_admission_proof() {
        let (_root, target) = tree();
        write_output(&target.join("retained"), 64 * 1024);
        let value = scanner(&target, &[]);
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        let warm = policy(&accounting);
        accounting.require_warm_pool(Some(&warm)).unwrap();
        accounting
            .observe_output(OutputScan {
                total: MIB / 2,
                records: None,
                pool_state: None,
                pool_bytes: 0,
                added: None,
            })
            .unwrap();
        assert_eq!(accounting.peak_growth, MIB / 2);
        let usage = accounting.usage(true, Some(9));
        assert_eq!(usage["complete"], true);
        assert_eq!(usage["exit_code"], 9);
        assert_eq!(usage["incremental"], Value::Null);
        assert_eq!(usage["admitted_pool"], warm["pools"][0]);
        let failure = accounting
            .observe_output(OutputScan {
                total: 2 * MIB,
                records: None,
                pool_state: None,
                pool_bytes: 0,
                added: None,
            })
            .unwrap_err();
        assert_eq!(failure.reason, "growth");
        assert_eq!(failure.growth, 2 * MIB);
    }

    #[test]
    fn warm_pool_requires_exact_identity_and_state_and_a_strict_buffer() {
        let (root, target) = tree();
        write_output(&target.join("retained"), 64 * 1024);
        let value = scanner(&target, &[]);
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        let warm = policy(&accounting);
        let boundary = accounting.budget - growth_buffer(accounting.budget);
        accounting.baseline = accounting.baseline_pool.as_ref().unwrap().retained_bytes + boundary;
        cold_failure(accounting.require_warm_pool(Some(&warm)), 2 * MIB);
        assert!(accounting.admitted_pool.is_none());
        accounting.baseline -= 1;
        accounting.require_warm_pool(Some(&warm)).unwrap();
        assert_eq!(accounting.unproven_baseline, boundary - 1);

        let other = root.path().join("other-target");
        fs::create_dir(&other).unwrap();
        write_output(&other.join("retained"), 64 * 1024);
        let other_scanner = scanner(&other, &[]);
        let mut other_accounting = Accounting::new(MIB, 0, &other_scanner, None, false).unwrap();
        cold_failure(other_accounting.require_warm_pool(Some(&warm)), 2 * MIB);

        write_output(&target.join("new"), 4096);
        let changed = scanner(&target, &[]);
        let mut changed_accounting = Accounting::new(MIB, 0, &changed, None, false).unwrap();
        cold_failure(changed_accounting.require_warm_pool(Some(&warm)), 2 * MIB);
    }

    #[test]
    fn unproven_source_baseline_remains_charged_after_cleanup_and_lost_learning() {
        let (root, target) = tree();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let retained = target.join("retained");
        write_output(&retained, 128 * 1024);
        let source_bytes = write_output(&source.join("input"), 64 * 1024);
        fs::hard_link(&retained, source.join("pool-alias")).unwrap();
        let value = scanner(&target, &[source.clone()]);
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        let warm = policy(&accounting);
        accounting.require_warm_pool(Some(&warm)).unwrap();
        assert!(accounting.unproven_baseline >= source_bytes);
        assert!(accounting.unproven_baseline < source_bytes * 2);
        fs::rename(source.join("input"), root.path().join("retained-input")).unwrap();
        let added = write_output(&target.join("new"), 32 * 1024);
        let scan = measure_outputs(
            &value.outputs,
            &target,
            value.initial.records.as_deref(),
            1,
            || {},
        )
        .unwrap();
        accounting.observe_output(scan).unwrap();
        assert!(accounting.peak_growth >= accounting.unproven_baseline + added);
        let usage = accounting.usage(true, Some(0));
        assert!(usage["incremental"].is_null());
        assert_eq!(usage["admitted_pool"], warm["pools"][0]);
    }

    #[test]
    fn free_space_rate_uses_probe_time_and_preserves_peak_drop() {
        let (_root, target) = tree();
        write_output(&target.join("retained"), 4096);
        let value = scanner(&target, &[]);
        let device = *value.devices.first().unwrap();
        let mut accounting = Accounting::new(40 * GIB, 10 * GIB, &value, None, false).unwrap();
        let start = Instant::now();
        accounting.admit(
            BTreeMap::from([(device, 33 * GIB)]),
            BTreeMap::from([(device, 10 * GIB)]),
            start,
        );
        accounting
            .observe_free(
                BTreeMap::from([(device, 27 * GIB)]),
                start + Duration::from_secs(10),
            )
            .unwrap();
        accounting
            .observe_free(
                BTreeMap::from([(device, 35 * GIB)]),
                start + Duration::from_secs(20),
            )
            .unwrap();
        assert_eq!(
            accounting.usage(true, Some(0))["incremental"]["peak_free_drop_bytes"],
            6 * GIB
        );
        let failure = accounting
            .observe_free(
                BTreeMap::from([(device, 34 * GIB)]),
                start + Duration::from_secs(20) + Duration::from_millis(1),
            )
            .unwrap_err();
        assert_eq!(failure.reason, "free_floor");
        assert_eq!(failure.free, 34 * GIB);
        let changed = accounting
            .observe_free(
                BTreeMap::from([(device.wrapping_add(1), 34 * GIB)]),
                start + Duration::from_secs(21),
            )
            .unwrap_err();
        assert_eq!(changed.reason, "monitor_unavailable");
    }

    #[test]
    fn cache_plan_and_warm_policy_have_closed_strict_schemas() {
        let (_root, target) = tree();
        write_output(&target.join("retained"), 4096);
        let value = scanner(&target, &[]);
        let accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        let valid = policy(&accounting);
        validate_warm_policy(Some(&valid), MIB).unwrap();
        let mut duplicate = valid.clone();
        duplicate["pools"][1] = duplicate["pools"][0].clone();
        assert!(
            validate_warm_policy(Some(&duplicate), MIB)
                .unwrap_err()
                .detail
                .contains("duplicate")
        );
        for malformed in [
            json!({"cold_growth_bytes": 2 * MIB, "pools": [null, null, null, null, null, null, null, null]}),
            json!({"cold_growth_bytes": 2 * MIB, "pools": valid["pools"], "extra": false}),
            json!({"cold_growth_bytes": true, "pools": valid["pools"]}),
            json!({"cold_growth_bytes": MIB, "pools": valid["pools"]}),
        ] {
            assert!(validate_warm_policy(Some(&malformed), MIB).is_err());
        }
        let mut malformed = valid.clone();
        malformed["pools"][0]["identity"][0] = json!(true);
        assert!(validate_warm_policy(Some(&malformed), MIB).is_err());
        malformed = valid.clone();
        malformed["pools"][0]["retained_bytes"] = json!(1.0);
        assert!(validate_warm_policy(Some(&malformed), MIB).is_err());
        assert!(validate_cargo_cache_plan(None, true).is_err());
        assert!(validate_cargo_cache_plan(Some(&Value::Null), false).is_ok());
        let mut cache = cache_plan(None);
        validate_cargo_cache_plan(Some(&cache), true).unwrap();
        cache["verified"] = json!(false);
        assert!(
            validate_cargo_cache_plan(Some(&cache), true)
                .unwrap_err()
                .detail
                .contains("literal absolute CARGO_HOME")
        );
        for name in [
            "../outside",
            "rch-cargo-cache-a/b",
            "rch-cargo-cache-$(id)",
            "rch-cargo-cache-é",
        ] {
            cache = cache_plan(None);
            cache["name"] = json!(name);
            assert!(validate_cargo_cache_plan(Some(&cache), false).is_err());
        }
        cache = cache_plan(None);
        cache["extra"] = json!(false);
        assert!(validate_cargo_cache_plan(Some(&cache), false).is_err());
    }

    #[test]
    fn cache_redirects_and_explicit_home_are_bound_and_only_missing_leaves_are_created() {
        let (root, _target) = tree();
        let base = root.path().join("base");
        let home = base.join("rch-cargo-cache-worker");
        fs::create_dir(&base).unwrap();
        fs::create_dir(&home).unwrap();
        let registry = root.path().join("registry-store");
        let git = root.path().join("git-store");
        let explicit = root.path().join("explicit-home");
        fs::create_dir(&git).unwrap();
        symlink(&registry, home.join("registry")).unwrap();
        symlink(&git, home.join("git")).unwrap();
        let plan = cache_plan(Some(&explicit));
        let (roots, aliases) =
            prepare_cargo_cache_roots(Some(&plan), Some(base.as_os_str())).unwrap();
        assert!(registry.is_dir());
        assert!(roots.contains(&registry));
        assert!(roots.contains(&git));
        assert!(roots.contains(&explicit));
        verify_cargo_cache_bindings(&aliases).unwrap();
        fs::rename(home.join("registry"), home.join("retained-registry-link")).unwrap();
        symlink(&git, home.join("registry")).unwrap();
        assert_eq!(
            verify_cargo_cache_bindings(&aliases).unwrap_err().reason,
            "monitor_unavailable"
        );

        let absent = root.path().join("absent-parent").join("home");
        let plan = cache_plan(Some(&absent));
        let error = prepare_cargo_cache_roots(Some(&plan), Some(base.as_os_str())).unwrap_err();
        assert!(error.detail.contains("parent must already exist"));
        assert!(!root.path().join("absent-parent").exists());
        let alias = root.path().join("base-alias");
        symlink(&base, &alias).unwrap();
        assert!(
            prepare_cargo_cache_roots(Some(&cache_plan(None)), Some(alias.as_os_str())).is_err()
        );
        for index in 0..48 {
            symlink(
                format!("chain-{}", index + 1),
                root.path().join(format!("chain-{index}")),
            )
            .unwrap();
        }
        assert_eq!(
            resolve_cache_path(&root.path().join("chain-0")).unwrap(),
            root.path().join("chain-48")
        );
        symlink("cycle-b", root.path().join("cycle-a")).unwrap();
        symlink("cycle-a", root.path().join("cycle-b")).unwrap();
        assert!(resolve_cache_path(&root.path().join("cycle-a")).is_err());
    }

    #[test]
    fn cache_walk_bound_counts_nested_entries_once_and_retains_floor_probes() {
        let (root, target) = tree();
        write_output(&target.join("retained"), 4096);
        let (base, plan, roots, _aliases) = cache_roots(root.path());
        let registry = base.join("rch-cargo-cache-worker/registry");
        for index in 0..3 {
            write_output(&registry.join(index.to_string()), 4096);
        }
        assert!(cache_walk_is_bounded(&roots, 5).unwrap());
        assert!(!cache_walk_is_bounded(&roots, 4).unwrap());
        let bounded = Scanner::with_limits(
            &target,
            &[target.clone()],
            &[],
            Some(&plan),
            "boot",
            Some(base.as_os_str()),
            4,
            100,
        )
        .unwrap();
        assert_eq!(bounded.outputs, [target.clone()]);
        assert!(roots.iter().all(|path| bounded.paths.contains(path)));
        let walked = Scanner::with_limits(
            &target,
            &[target.clone()],
            &[],
            Some(&plan),
            "boot",
            Some(base.as_os_str()),
            5,
            100,
        )
        .unwrap();
        assert!(roots.iter().all(|path| walked.outputs.contains(path)));
        assert!(walked.initial.total > bounded.initial.total);
    }

    #[test]
    fn cargo_cache_allocations_cannot_borrow_pool_credit_or_hide_behind_cleanup() {
        let (root, target) = tree();
        let retained = target.join("retained");
        write_output(&retained, 128 * 1024);
        let (base, plan, _roots, _aliases) = cache_roots(root.path());
        let registry = base.join("rch-cargo-cache-worker/registry");
        let cache_bytes = write_output(&registry.join("retained"), 64 * 1024);
        let value = Scanner::with_limits(
            &target,
            &[target.clone()],
            &[],
            Some(&plan),
            "boot",
            Some(base.as_os_str()),
            100,
            100,
        )
        .unwrap();
        let mut too_small = Accounting::new(cache_bytes, 0, &value, None, false).unwrap();
        let warm = policy(&too_small);
        cold_failure(too_small.require_warm_pool(Some(&warm)), cache_bytes * 2);
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        let warm = policy(&accounting);
        accounting.require_warm_pool(Some(&warm)).unwrap();
        assert!(accounting.unproven_baseline >= cache_bytes);
        fs::rename(&retained, root.path().join("retained-outside")).unwrap();
        let new_bytes = write_output(&registry.join("download"), 32 * 1024);
        let scan = value.scan().unwrap();
        assert!(scan.total < value.initial.total);
        accounting.observe_output(scan).unwrap();
        assert!(accounting.peak_growth >= accounting.unproven_baseline + new_bytes);
    }

    #[test]
    fn output_volume_not_listed_in_probes_is_still_sampled_and_floor_protected() {
        let (root, target) = tree();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let value =
            Scanner::new(&target, &[target.clone()], &[source.clone()], None, "boot").unwrap();
        assert!(value.paths.contains(&source));
        let (samples, sampled_at) = value.sample().unwrap();
        assert_eq!(value.devices, samples.keys().copied().collect());
        let device = *value.devices.first().unwrap();
        let free = samples[&device];
        let mut accounting = Accounting::new(MIB, 0, &value, None, false).unwrap();
        accounting.admit(
            samples.clone(),
            BTreeMap::from([(device, free)]),
            sampled_at,
        );
        assert_eq!(
            accounting
                .observe_free(samples, sampled_at + Duration::from_secs(1))
                .unwrap_err()
                .reason,
            "free_floor"
        );
    }

    #[test]
    fn reading_retained_artifacts_preserves_the_pool_fingerprint() {
        let (_root, target) = tree();
        let retained = target.join("retained");
        write_output(&retained, 4096);
        let value = scanner(&target, &[]);
        assert!(!fs::read(&retained).unwrap().is_empty());
        assert_eq!(value.scan().unwrap().pool_state, value.initial.pool_state);
    }
}
