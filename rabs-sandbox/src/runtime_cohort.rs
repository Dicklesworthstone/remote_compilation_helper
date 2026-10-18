//! Measured Linux host compatibility for remote leaf rustc execution.
//!
//! The transferred toolchain covers rustc and its internal libraries, but not
//! the host ELF interpreter, libc or other libraries exposed through /usr.
//! Resolve the actual ELF runtime with a clean, bounded loader probe, hash
//! stable external library bytes, and bind stable CPU/kernel/filesystem facts.
//! Internal paths are relative to the retained toolchain: physical placement
//! does not participate in identity.
//!
//! This is a compatibility observation, not a sandbox or immutable mount.
//! Callers retain the toolchain, compare edge and worker digests before spawn,
//! and reobserve after execution before offering a result. The namespace must
//! separately preserve subscriber paths, exact environment and input closure.
//! No hostname, PID, core count, frequency, load or configured label is keyed.

use rabs_protocol::result_identity::TypedDigest;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Fixed identity domain shared with the remote dependency key builder.
pub const RUNTIME_COHORT_DOMAIN: &str = "rabs.rustc-host-runtime.v1";

/// An observation that cannot support remote result publication.
#[derive(Debug)]
pub enum RuntimeCohortError {
    /// The platform or loader format is outside this observer's contract.
    Unsupported(&'static str),
    /// Missing, inconsistent, changing or excessive observation data.
    Invalid(&'static str),
    /// Filesystem or bounded process observation failed.
    Io(io::Error),
}

impl fmt::Display for RuntimeCohortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(detail) => write!(formatter, "runtime cohort unsupported: {detail}"),
            Self::Invalid(detail) => write!(formatter, "runtime cohort invalid: {detail}"),
            Self::Io(error) => write!(formatter, "runtime cohort observation: {error}"),
        }
    }
}

impl std::error::Error for RuntimeCohortError {}

impl From<io::Error> for RuntimeCohortError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

/// Observe the host runtime used by one retained compiler.
///
/// Paths are physical local paths. The loader search list contains only
/// ordered directories inside the toolchain root, translated from the admitted
/// invocation's LD_LIBRARY_PATH; private empty output/dependency entries are
/// omitted. The adapter must refuse empty loader components, other LD_*
/// controls and GLIBC_TUNABLES before supplying the actual execution environment.
///
/// The filesystem root is a writable private staging directory on the source
/// and output materialization filesystem. An owned child probes actual case,
/// Unicode and timestamp behavior and is removed on return. Stable filesystem
/// type and name limits are bound; path names and free space are not.
///
/// Keep the toolchain immutable across observation and compilation. External
/// host libraries are stable-read and path-revalidated during observation;
/// rerun after compilation to detect a changed cohort.
///
/// # Errors
/// Refuses non-Linux/non-ELF hosts, unresolved libraries, unsupported probe
/// output, unclosed loader paths, changing files and exhausted bounds.
pub fn observe_runtime_cohort(
    compiler: &Path,
    toolchain_root: &Path,
    loader_search_paths: &[PathBuf],
    filesystem_root: &Path,
) -> Result<TypedDigest, RuntimeCohortError> {
    #[cfg(target_os = "linux")]
    { linux::observe(compiler, toolchain_root, loader_search_paths, filesystem_root) }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (compiler, toolchain_root, loader_search_paths, filesystem_root);
        Err(RuntimeCohortError::Unsupported("Linux ELF runtime required"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, FileTimes, OpenOptions};
    use std::io::Read;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    const MAX_PROBE_BYTES: u64 = 64 * 1024;
    const MAX_CPUINFO_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_LIBRARIES: usize = 128;
    const MAX_LIBRARY_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_EXTERNAL_BYTES: u64 = 256 * 1024 * 1024;
    static NEXT_PROBE: AtomicU64 = AtomicU64::new(1);

    fn invalid(detail: &'static str) -> RuntimeCohortError {
        RuntimeCohortError::Invalid(detail)
    }

    fn append(bytes: &mut Vec<u8>, field: &[u8]) {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field);
    }

    fn digest(bytes: &[u8]) -> TypedDigest {
        let mut hasher = Sha256::new();
        hasher.update(RUNTIME_COHORT_DOMAIN.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: RUNTIME_COHORT_DOMAIN,
            bytes: hasher.finalize().into(),
        }
    }

    fn bounded_read(reader: impl Read, maximum: u64) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        reader.take(maximum + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(io::Error::other("runtime observation byte limit exceeded"));
        }
        Ok(bytes)
    }

    fn read_system(path: &str, maximum: u64) -> Result<Vec<u8>, RuntimeCohortError> {
        bounded_read(crate::regular_input::open(Path::new(path))?, maximum).map_err(Into::into)
    }

    fn probe_targets(compiler: &Path, root: &Path) -> Result<Vec<PathBuf>, RuntimeCohortError> {
        // Backend DSOs may be dlopen-loaded even by a metadata-only compile.
        // Include their DT_NEEDED closure instead of assuming that ldd rustc
        // alone covers the runtime. The retained dataset owns their bytes.
        let mut targets = BTreeSet::from([compiler.to_path_buf()]);
        let mut entries_left = 4096_usize;
        let mut directories = vec![root.join("lib")];
        let rustlib = root.join("lib/rustlib");
        match fs::read_dir(&rustlib) {
            Ok(entries) => {
                for entry in entries {
                    entries_left = entries_left.checked_sub(1)
                        .ok_or_else(|| invalid("runtime enumeration entry budget exhausted"))?;
                    let path = entry?.path().join("codegen-backends");
                    match fs::metadata(&path) {
                        Ok(metadata) if metadata.is_dir() => directories.push(path),
                        Ok(_) => return Err(invalid("codegen backend root is not a directory")),
                        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => {}
                        Err(error) => return Err(error.into()),
                    }
                    if directories.len() > 128 {
                        return Err(invalid("too many codegen backend directories"));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for directory in directories {
            let entries = match fs::read_dir(directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                entries_left = entries_left.checked_sub(1)
                    .ok_or_else(|| invalid("runtime enumeration entry budget exhausted"))?;
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| invalid("non-UTF-8 runtime member name"))?;
                if !name.starts_with("lib") || !name.contains(".so") { continue; }
                let path = fs::canonicalize(entry.path())?;
                if !path.starts_with(root) || !fs::metadata(&path)?.is_file() {
                    return Err(invalid("runtime DSO leaves the retained toolchain"));
                }
                targets.insert(path);
                if targets.len() > 32 { return Err(invalid("too many retained runtime DSOs")); }
            }
        }
        Ok(targets.into_iter().collect())
    }

    fn without_probe_headers(
        output: &[u8],
        targets: &[PathBuf],
    ) -> Result<Vec<u8>, RuntimeCohortError> {
        let text = std::str::from_utf8(output).map_err(|_| invalid("non-UTF-8 loader output"))?;
        let mut flat = Vec::new();
        for line in text.lines() {
            if let Some(header) = line.trim().strip_suffix(':') {
                if !targets.iter().any(|path| path.to_str() == Some(header)) {
                    return Err(invalid("loader reported an unrequested probe target"));
                }
                continue;
            }
            flat.extend_from_slice(line.as_bytes());
            flat.push(b'\n');
        }
        Ok(flat)
    }

    fn probe(targets: &[PathBuf], search: &[PathBuf]) -> Result<Vec<u8>, RuntimeCohortError> {
        // Fixed tools and a clean environment: daemon PATH/LD_* never select
        // the probe or change its resolution. GNU timeout owns the ldd process
        // group and kills it at the deadline. Capped concurrent readers bound
        // output without blocking one pipe behind the other.
        let mut command = Command::new("/usr/bin/timeout");
        command
            .args(["--signal=KILL", "5s", "/usr/bin/ldd", "--"])
            .args(targets)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !search.is_empty() {
            command.env(
                "LD_LIBRARY_PATH",
                std::env::join_paths(search).map_err(|_| invalid("invalid loader search path"))?,
            );
        }
        let mut child = command.spawn()?;
        let stdout = child.stdout.take().ok_or_else(|| invalid("missing probe stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| invalid("missing probe stderr"))?;
        let output_reader = std::thread::spawn(move || bounded_read(stdout, MAX_PROBE_BYTES));
        let error_reader = std::thread::spawn(move || bounded_read(stderr, MAX_PROBE_BYTES));
        let status = child.wait();
        let output = output_reader.join();
        let errors = error_reader.join();
        let output = output.map_err(|_| invalid("probe stdout reader panicked"))??;
        let errors = errors.map_err(|_| invalid("probe stderr reader panicked"))??;
        if !status?.success() {
            return Err(invalid("ELF loader probe failed or exceeded its deadline"));
        }
        if !errors.is_empty() {
            return Err(invalid("ELF loader probe reported unresolved runtime evidence"));
        }
        without_probe_headers(&output, targets)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Library {
        name: String,
        path: PathBuf,
    }

    fn libraries(stdout: &[u8]) -> Result<Vec<Library>, RuntimeCohortError> {
        let stdout = std::str::from_utf8(stdout).map_err(|_| invalid("non-UTF-8 loader output"))?;
        let mut result = BTreeMap::new();
        for line in stdout.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let (entry, address) = line.rsplit_once(" (")
                .ok_or_else(|| invalid("unresolved or unsupported ELF loader output"))?;
            address.strip_suffix(')')
                .and_then(|value| value.strip_prefix("0x"))
                .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .ok_or_else(|| invalid("invalid ELF loader address"))?;
            if matches!(entry, "linux-vdso.so.1" | "linux-gate.so.1") {
                continue; // Actual kernel ABI is bound below; ASLR is not.
            }
            let (name, path) = entry.split_once(" => ").unwrap_or((entry, entry));
            if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_whitespace())
                || !path.starts_with('/') || path.len() > 4096
                || path.bytes().any(|byte| byte.is_ascii_whitespace() || byte == 0)
            {
                return Err(invalid("nonabsolute or unrepresentable ELF library path"));
            }
            if result.len() >= MAX_LIBRARIES && !result.contains_key(name) {
                return Err(invalid("too many runtime libraries"));
            }
            let path = PathBuf::from(path);
            if let Some(previous) = result.insert(name.to_owned(), path.clone())
                && previous != path
            {
                return Err(invalid("one ELF library name resolves to different paths"));
            }
        }
        if result.is_empty() {
            return Err(invalid("ELF loader did not report a runtime closure"));
        }
        Ok(result.into_iter().map(|(name, path)| Library { name, path }).collect())
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        size: u64,
        mode: u32,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl Stamp {
        fn of(metadata: &fs::Metadata) -> Self {
            Self {
                device: metadata.dev(), inode: metadata.ino(), size: metadata.len(),
                mode: metadata.mode(), modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }

    fn external_bytes(path: &Path, budget: &mut u64) -> Result<[u8; 32], RuntimeCohortError> {
        let mut held = crate::regular_input::open(path)?;
        let before = Stamp::of(&held.metadata()?);
        if before.size > MAX_LIBRARY_BYTES || before.size > *budget {
            return Err(invalid("external runtime exceeds its byte budget"));
        }
        *budget -= before.size;
        let mut copied = 0_u64;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = held.read(&mut buffer)?;
            if count == 0 { break; }
            copied = copied.checked_add(count as u64)
                .filter(|count| *count <= before.size)
                .ok_or_else(|| invalid("runtime library grew during observation"))?;
            hasher.update(&buffer[..count]);
        }
        if copied != before.size || Stamp::of(&held.metadata()?) != before
            || Stamp::of(&fs::metadata(path)?) != before
        {
            return Err(invalid("runtime library changed during observation"));
        }
        Ok(hasher.finalize().into())
    }

    fn library_record(
        library: &Library,
        root: &Path,
        budget: &mut u64,
    ) -> Result<Vec<u8>, RuntimeCohortError> {
        let resolved = fs::canonicalize(&library.path)?;
        let mut record = Vec::new();
        if let Ok(relative) = resolved.strip_prefix(root) {
            // Bytes and symlinks are pinned by the retained toolchain. Avoid
            // rehashing hundreds of megabytes of LLVM on every observation.
            if !fs::metadata(&resolved)?.is_file() {
                return Err(invalid("toolchain runtime member is not regular"));
            }
            append(&mut record, b"retained-toolchain");
            append(&mut record, relative.to_str().ok_or_else(|| invalid("non-UTF-8 toolchain member"))?.as_bytes());
            if !library.name.starts_with('/') {
                append(&mut record, library.name.as_bytes());
            }
        } else {
            append(&mut record, b"host-runtime");
            append(&mut record, library.name.as_bytes());
            append(&mut record, library.path.to_str().ok_or_else(|| invalid("non-UTF-8 runtime path"))?.as_bytes());
            append(&mut record, resolved.to_str().ok_or_else(|| invalid("non-UTF-8 resolved runtime path"))?.as_bytes());
            append(&mut record, &external_bytes(&resolved, budget)?);
        }
        if fs::canonicalize(&library.path)? != resolved {
            return Err(invalid("runtime library path changed during observation"));
        }
        Ok(record)
    }

    fn cpu_profile(raw: &[u8]) -> Result<Vec<u8>, RuntimeCohortError> {
        let text = std::str::from_utf8(raw).map_err(|_| invalid("non-UTF-8 CPU identity"))?;
        let fields: &[&str] = match std::env::consts::ARCH {
            "x86_64" => &["vendor_id", "cpu family", "model", "stepping", "model name", "flags"],
            "aarch64" => &["CPU implementer", "CPU architecture", "CPU variant", "CPU part", "CPU revision", "Features"],
            _ => return Err(RuntimeCohortError::Unsupported("unsupported CPU architecture")),
        };
        let mut profiles = BTreeSet::new();
        for block in text.split("\n\n") {
            let mut values = BTreeMap::new();
            for line in block.lines() {
                let Some((name, value)) = line.split_once(':') else { continue };
                let name = name.trim();
                if fields.contains(&name) {
                    let normalized = if matches!(name, "flags" | "Features") {
                        value.split_whitespace().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(" ")
                    } else {
                        value.split_whitespace().collect::<Vec<_>>().join(" ")
                    };
                    if normalized.is_empty() || values.insert(name, normalized).is_some() {
                        return Err(invalid("empty or duplicate CPU identity field"));
                    }
                }
            }
            if values.is_empty() { continue; }
            if fields.iter().any(|name| !values.contains_key(name)) {
                return Err(invalid("incomplete CPU model or feature identity"));
            }
            let mut profile = Vec::new();
            for (name, value) in values {
                append(&mut profile, name.as_bytes());
                append(&mut profile, value.as_bytes());
            }
            profiles.insert(profile);
        }
        if profiles.is_empty() {
            return Err(invalid("missing CPU model and feature identity"));
        }
        let mut result = Vec::new();
        append(&mut result, std::env::consts::ARCH.as_bytes());
        for profile in profiles { append(&mut result, &profile); }
        Ok(result)
    }

    struct ProbeDirectory(PathBuf);

    impl ProbeDirectory {
        fn new(parent: &Path) -> Result<Self, RuntimeCohortError> {
            if !parent.is_absolute() || !fs::metadata(parent)?.is_dir() {
                return Err(invalid("filesystem probe requires a private absolute directory"));
            }
            for _ in 0..64 {
                let sequence = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(".rabs-runtime-fs-{}-{sequence}", std::process::id()));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(invalid("filesystem probe name budget exhausted"))
        }
    }

    impl Drop for ProbeDirectory {
        fn drop(&mut self) {
            // Only a create-new child owned by this probe is removed.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn filesystem_profile(root: &Path) -> Result<Vec<u8>, RuntimeCohortError> {
        let directory = ProbeDirectory::new(root)?;
        let path = directory.0.join("case");
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        if directory.0.join("CASE").try_exists()? {
            return Err(RuntimeCohortError::Unsupported("case-sensitive filesystem required"));
        }
        let unicode = directory.0.join("u\u{e9}");
        let _unicode_file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(unicode)?;
        if directory.0.join("ue\u{301}").try_exists()? {
            return Err(RuntimeCohortError::Unsupported("byte-distinct Unicode filenames required"));
        }
        let modified = UNIX_EPOCH + Duration::from_secs(1_600_000_000) + Duration::from_nanos(123_456_789);
        file.set_times(FileTimes::new().set_modified(modified))?;
        let observed = file.metadata()?.modified()?.duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("filesystem timestamp is not representable"))?;
        let statistics = rustix::fs::statfs(&directory.0).map_err(io::Error::from)?;
        let mut profile = Vec::new();
        append(&mut profile, b"case-sensitive.unicode-bytes.regular-files.v1");
        append(&mut profile, statistics.f_type.to_string().as_bytes());
        append(&mut profile, statistics.f_namelen.to_string().as_bytes());
        append(&mut profile, &observed.as_secs().to_le_bytes());
        append(&mut profile, &observed.subsec_nanos().to_le_bytes());
        Ok(profile)
    }

    pub(super) fn observe(
        compiler: &Path,
        toolchain_root: &Path,
        loader_search_paths: &[PathBuf],
        filesystem_root: &Path,
    ) -> Result<TypedDigest, RuntimeCohortError> {
        if !compiler.is_absolute() || !toolchain_root.is_absolute() || loader_search_paths.len() > 128 {
            return Err(invalid("runtime paths must be absolute and bounded"));
        }
        let root = fs::canonicalize(toolchain_root)?;
        let compiler = fs::canonicalize(compiler)?;
        if !compiler.starts_with(&root) || !fs::metadata(&root)?.is_dir() {
            return Err(invalid("compiler is outside the retained toolchain"));
        }
        let mut executable = crate::regular_input::open(&compiler)?;
        let compiler_stamp = Stamp::of(&executable.metadata()?);
        let mut magic = [0_u8; 4];
        executable.read_exact(&mut magic)?;
        if magic != *b"\x7fELF" {
            return Err(RuntimeCohortError::Unsupported("compiler is not an ELF binary"));
        }
        match read_system("/etc/ld.so.preload", MAX_PROBE_BYTES) {
            Ok(bytes) if bytes.iter().any(|byte| !byte.is_ascii_whitespace()) =>
                return Err(RuntimeCohortError::Unsupported("global loader preloads are not exposed in the action namespace")),
            Ok(_) => {}
            Err(RuntimeCohortError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut search = Vec::new();
        for path in loader_search_paths {
            if !path.is_absolute() { return Err(invalid("loader search directory is not absolute")); }
            let resolved = fs::canonicalize(path)?;
            if !resolved.starts_with(&root) || !fs::metadata(&resolved)?.is_dir() {
                return Err(invalid("loader search directory leaves the retained toolchain"));
            }
            search.push(resolved);
        }
        let targets = probe_targets(&compiler, &root)?;
        let libraries = libraries(&probe(&targets, &search)?)?;
        let mut records = Vec::new();
        let mut budget = MAX_EXTERNAL_BYTES;
        for library in libraries {
            let resolved = fs::canonicalize(&library.path)?;
            if !resolved.starts_with(&root) && !resolved.starts_with("/usr") {
                return Err(RuntimeCohortError::Unsupported("external library is not in the worker's read-only /usr view"));
            }
            records.push(library_record(&library, &root, &mut budget)?);
        }
        records.sort();
        let mut observed = Vec::new();
        append(&mut observed, b"elf-host-cohort-v1");
        for record in records { append(&mut observed, &record); }
        for path in ["/proc/sys/kernel/ostype", "/proc/sys/kernel/osrelease"] {
            let raw = read_system(path, 4096)?;
            let value = std::str::from_utf8(&raw).map_err(|_| invalid("non-UTF-8 kernel identity"))?.trim();
            if value.is_empty() { return Err(invalid("empty kernel identity")); }
            append(&mut observed, value.as_bytes());
        }
        append(&mut observed, &cpu_profile(&read_system("/proc/cpuinfo", MAX_CPUINFO_BYTES)?)?);
        append(&mut observed, &filesystem_profile(filesystem_root)?);
        if Stamp::of(&executable.metadata()?) != compiler_stamp
            || Stamp::of(&fs::metadata(&compiler)?) != compiler_stamp
        {
            return Err(invalid("compiler changed during runtime observation"));
        }
        Ok(digest(&observed))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn loader_addresses_are_ignored_but_unresolved_and_relative_paths_are_refused() {
            let a = b"linux-vdso.so.1 (0x1111)\nlibc.so.6 => /lib/libc.so.6 (0x2222)\n/lib64/ld-linux.so.2 (0x3333)\n";
            let b = b"linux-vdso.so.1 (0x9999)\n/lib64/ld-linux.so.2 (0xaaaa)\nlibc.so.6 => /lib/libc.so.6 (0xbbbb)\n";
            assert_eq!(libraries(a).unwrap(), libraries(b).unwrap());
            for bad in [
                b"libmissing.so => not found\n".as_slice(),
                b"libc.so => relative/libc.so (0x1234)\n",
                b"statically linked\n",
                b"libc.so => /lib/libc.so (invalid)\n",
                b"linux-vdso.so.1 (0x1234)\n",
            ] { assert!(libraries(bad).is_err(), "{bad:?}"); }
        }

        #[test]
        fn dlopen_backend_targets_are_included_and_probe_headers_are_exact() {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("toolchain");
            let backend = root.join("lib/rustlib/host/codegen-backends");
            fs::create_dir_all(&backend).unwrap();
            fs::create_dir(root.join("bin")).unwrap();
            let compiler = root.join("bin/rustc");
            let driver = root.join("lib/librustc_driver.so");
            let codegen = backend.join("librustc_codegen_llvm.so");
            for path in [&compiler, &driver, &codegen] { fs::write(path, b"fixture").unwrap(); }
            let targets = probe_targets(&compiler, &root).unwrap();
            assert_eq!(targets.len(), 3);
            for path in [&compiler, &driver, &codegen] { assert!(targets.contains(path)); }
            let raw = format!("{}:\nlibc.so => /lib/libc.so (0x1234)\n{}:\nlibz.so => /lib/libz.so (0x2345)\n",
                compiler.display(), codegen.display());
            let flattened = without_probe_headers(raw.as_bytes(), &targets).unwrap();
            assert_eq!(libraries(&flattened).unwrap().len(), 2);
            assert!(without_probe_headers(b"/unrequested/compiler:\n", &targets).is_err());
        }

        #[test]
        fn external_library_byte_changes_change_the_runtime_record() {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("toolchain");
            fs::create_dir(&root).unwrap();
            let path = directory.path().join("libexternal.so");
            fs::write(&path, b"first runtime bytes").unwrap();
            let library = Library { name: "libexternal.so".into(), path: path.clone() };
            let mut budget = MAX_EXTERNAL_BYTES;
            let first = library_record(&library, &root, &mut budget).unwrap();
            fs::write(path, b"different runtime bytes").unwrap();
            let mut budget = MAX_EXTERNAL_BYTES;
            let changed = library_record(&library, &root, &mut budget).unwrap();
            assert_ne!(first, changed);
            assert_ne!(digest(&first), digest(&changed));
        }

        #[test]
        fn retained_toolchain_placement_is_not_runtime_identity() {
            let directory = tempfile::tempdir().unwrap();
            let mut records = Vec::new();
            for name in ["edge-toolchain", "worker-retained-123"] {
                let root = directory.path().join(name);
                fs::create_dir_all(root.join("lib")).unwrap();
                let path = root.join("lib/libinternal.so");
                fs::write(&path, b"same retained bytes").unwrap();
                let mut budget = MAX_EXTERNAL_BYTES;
                records.push(library_record(&Library { name: "libinternal.so".into(), path }, &root, &mut budget).unwrap());
            }
            assert_eq!(records[0], records[1]);
        }

        #[test]
        fn actual_filesystem_measurement_is_stable_across_private_roots() {
            let left = tempfile::tempdir().unwrap();
            let right = tempfile::tempdir().unwrap();
            assert_eq!(filesystem_profile(left.path()).unwrap(), filesystem_profile(right.path()).unwrap());
            assert_eq!(fs::read_dir(left.path()).unwrap().count(), 0);
            assert_eq!(fs::read_dir(right.path()).unwrap().count(), 0);
        }

        #[cfg(target_arch = "x86_64")]
        #[test]
        fn cpu_frequency_processor_number_and_feature_order_are_not_identity() {
            let a = b"processor: 0\nvendor_id: GenuineIntel\ncpu family: 6\nmodel: 143\nstepping: 8\nmodel name: Example CPU\ncpu MHz: 900\nflags: sse avx avx2\n";
            let b = b"processor: 19\nvendor_id: GenuineIntel\ncpu family: 6\nmodel: 143\nstepping: 8\nmodel name: Example CPU\ncpu MHz: 3600\nflags: avx2 sse avx\n";
            assert_eq!(cpu_profile(a).unwrap(), cpu_profile(b).unwrap());
            let changed = String::from_utf8(b.to_vec()).unwrap().replace("avx2", "avx512f");
            assert_ne!(cpu_profile(a).unwrap(), cpu_profile(changed.as_bytes()).unwrap());
            assert!(cpu_profile(b"processor: 0\nflags: sse\n").is_err());
        }

        #[test]
        fn running_elf_runtime_observation_is_repeatable() {
            // Real ELF loader/CPU/filesystem observation of this executable;
            // not evidence of a remote rustc compile or authenticated delivery.
            let compiler = std::env::current_exe().unwrap();
            let root = compiler.parent().unwrap();
            let scratch = tempfile::tempdir().unwrap();
            let first = observe(&compiler, root, &[], scratch.path()).unwrap();
            let second = observe(&compiler, root, &[], scratch.path()).unwrap();
            assert_eq!(first, second);
            assert_eq!(first.domain, RUNTIME_COHORT_DOMAIN);
        }
    }
}
