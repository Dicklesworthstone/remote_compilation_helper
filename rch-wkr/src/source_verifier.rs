//! Native verification of the dispatcher's exact source-content manifest.
//!
//! The source grant and complete namespace barrier remain the caller's job.
//! This command independently checks every selected byte, entry type and
//! executable bit. It emits one success frame only after the whole manifest
//! and its denominators have been verified; it never repairs worker files.

use std::io::{Read, Write};
use std::path::Path;

const PROBE_REPLY: &str = "RCH_SOURCE_CONTENT_VERIFIER_V1";
#[cfg(unix)]
const MAX_FILES: usize = 100_000;
#[cfg(unix)]
const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
#[cfg(unix)]
const MAX_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
#[cfg(unix)]
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug)]
struct Failure {
    code: i32,
    reason: String,
}

fn refused(code: i32, reason: &str, relative: &str) -> Failure {
    Failure {
        code,
        reason: if relative.is_empty() {
            reason.to_owned()
        } else {
            format!("{reason}:{relative}")
        },
    }
}

fn malformed() -> Failure {
    refused(69, "read_or_manifest", "")
}

/// Run before the async runtime starts. The manifest is finite stdin data,
/// never an exec argument; paths containing shell syntax stay literal.
pub(crate) fn main(arguments: &[String]) -> i32 {
    if arguments == ["probe"] {
        return if writeln!(std::io::stdout().lock(), "{PROBE_REPLY}").is_ok() {
            0
        } else {
            69
        };
    }
    let result = (|| {
        let [operation, root, count, total] = arguments else {
            return Err(malformed());
        };
        if operation != "verify" {
            return Err(malformed());
        }
        let count = parse_decimal(count).ok_or_else(malformed)?;
        let total = parse_decimal(total).ok_or_else(malformed)?;
        let count = usize::try_from(count).map_err(|_| malformed())?;
        verify(Path::new(root), count, total, std::io::stdin().lock())?;
        writeln!(
            std::io::stdout().lock(),
            "RCH_SOURCE_CONTENT_VERIFIED\t{count}\t{total}"
        )
        .map_err(|_| malformed())
    })();
    match result {
        Ok(()) => 0,
        Err(failure) => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "RCH_SOURCE_CONTENT_ERROR:{}",
                failure.reason
            );
            failure.code
        }
    }
}

fn parse_decimal(text: &str) -> Option<u64> {
    let value = text.parse::<u64>().ok()?;
    (value.to_string() == text).then_some(value)
}

#[cfg(unix)]
struct Entry<'a> {
    hash: &'a str,
    bytes: u64,
    kind: &'a str,
    path: &'a str,
}

#[cfg(unix)]
fn entries(payload: &[u8], expected_count: usize) -> Result<Vec<Entry<'_>>, Failure> {
    if !payload.is_empty() && !payload.ends_with(b"\n") {
        return Err(refused(67, "count", ""));
    }
    let text = std::str::from_utf8(payload).map_err(|_| malformed())?;
    // Refuse at the first surplus row. A bounded but newline-dense request
    // must not amplify into millions of allocated line references.
    let lines: Vec<_> = text
        .split_terminator('\n')
        .take(expected_count.saturating_add(1))
        .collect();
    if lines.len() != expected_count {
        return Err(refused(67, "count", &lines.len().to_string()));
    }
    let mut paths = std::collections::HashSet::with_capacity(lines.len());
    lines
        .into_iter()
        .map(|line| {
            let mut fields = line.split('\t');
            let hash = fields.next().ok_or_else(malformed)?;
            let bytes = parse_decimal(fields.next().ok_or_else(malformed)?)
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or_else(malformed)?;
            let kind = fields.next().ok_or_else(malformed)?;
            let path = fields.next().ok_or_else(malformed)?;
            if path.is_empty() {
                return Err(refused(62, "empty_path", ""));
            }
            if path.len() > MAX_PATH_BYTES
                || path.contains('\\')
                || path.chars().any(char::is_control)
                || path.split('/').any(|part| matches!(part, "" | "." | ".."))
            {
                return Err(refused(62, "unsafe_path", ""));
            }
            if fields.next().is_some()
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !matches!(kind, "0" | "1" | "L")
                || !paths.insert(path)
            {
                return Err(malformed());
            }
            Ok(Entry {
                hash,
                bytes,
                kind,
                path,
            })
        })
        .collect()
}

#[cfg(unix)]
fn verify(root: &Path, count: usize, total: u64, input: impl Read) -> Result<(), Failure> {
    if count > MAX_FILES || total > MAX_BYTES || !root.is_absolute() {
        return Err(malformed());
    }
    let mut payload = Vec::new();
    input
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|_| malformed())?;
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(refused(69, "manifest_limit", ""));
    }
    let entries = entries(&payload, count)?;
    entries
        .iter()
        .try_fold(MAX_BYTES, |remaining, entry| {
            remaining.checked_sub(entry.bytes)
        })
        .ok_or_else(malformed)?;
    imp::verify(root, &entries, total)
}

#[cfg(not(unix))]
fn verify(_: &Path, _: usize, _: u64, _: impl Read) -> Result<(), Failure> {
    Err(refused(69, "platform_unsupported", ""))
}

#[cfg(unix)]
mod imp {
    use super::{Entry, Failure, Path, Read, malformed, refused};
    use rustix::fd::{AsFd, OwnedFd};
    use rustix::fs::{Access, AtFlags, FileType, Mode, OFlags, Stat};
    use sha2::{Digest as _, Sha256};

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn same_generation(left: &Stat, right: &Stat) -> bool {
        same_inode(left, right)
            && left.st_mode == right.st_mode
            && left.st_nlink == right.st_nlink
            && left.st_uid == right.st_uid
            && left.st_gid == right.st_gid
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    fn directory_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn named(parent: impl AsFd, name: &str) -> Result<Stat, Failure> {
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| malformed())
    }

    fn check_link_target(relative: &str, bytes: &[u8]) -> Result<(), Failure> {
        let target =
            std::str::from_utf8(bytes).map_err(|_| refused(63, "unsafe_symlink", relative))?;
        if target.is_empty()
            || target.starts_with('/')
            || target.contains('\\')
            || target.chars().any(char::is_control)
        {
            return Err(refused(63, "unsafe_symlink", relative));
        }
        let mut depth = relative.split('/').count() - 1;
        for component in target.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| refused(63, "symlink_escape", relative))?;
                }
                _ => depth += 1,
            }
        }
        Ok(())
    }

    fn hash_matches(hasher: Sha256, expected: &str) -> bool {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(64);
        for byte in hasher.finalize() {
            let _ = write!(hex, "{byte:02x}");
        }
        hex == expected
    }

    fn verify_entry(root: &OwnedFd, entry: &Entry<'_>) -> Result<u64, Failure> {
        let parts: Vec<_> = entry.path.split('/').collect();
        let name = parts.last().ok_or_else(malformed)?;
        let mut parents: Vec<OwnedFd> = Vec::new();
        for part in &parts[..parts.len() - 1] {
            let parent = parents.last().unwrap_or(root);
            let child = rustix::fs::openat(parent, *part, directory_flags(), Mode::empty())
                .map_err(|_| refused(63, "not_directory", entry.path))?;
            parents.push(child);
        }
        let parent = parents.last().unwrap_or(root);
        let before = named(parent, name).map_err(|_| {
            refused(
                63,
                if entry.kind == "L" {
                    "not_symlink"
                } else {
                    "not_regular"
                },
                entry.path,
            )
        })?;
        let mut hasher = Sha256::new();
        let bytes;
        if entry.kind == "L" {
            if FileType::from_raw_mode(before.st_mode) != FileType::Symlink {
                return Err(refused(63, "not_symlink", entry.path));
            }
            let target = rustix::fs::readlinkat(parent, *name, Vec::new())
                .map_err(|_| refused(63, "not_symlink", entry.path))?;
            check_link_target(entry.path, target.as_bytes())?;
            bytes = target.as_bytes().len() as u64;
            hasher.update(target.as_bytes());
        } else {
            if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
                return Err(refused(63, "not_regular", entry.path));
            }
            let fd = rustix::fs::openat(
                parent,
                *name,
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| refused(63, "not_regular", entry.path))?;
            let opened = rustix::fs::fstat(&fd).map_err(|_| malformed())?;
            if !same_generation(&before, &opened) {
                return Err(refused(69, "changed", entry.path));
            }
            let mut file = std::fs::File::from(fd);
            let mut limited = (&mut file).take(entry.bytes + 1);
            let mut buffer = [0_u8; 64 * 1024];
            let mut read_bytes = 0_u64;
            loop {
                let read = limited.read(&mut buffer).map_err(|_| malformed())?;
                if read == 0 {
                    break;
                }
                read_bytes += read as u64;
                hasher.update(&buffer[..read]);
            }
            bytes = read_bytes;
            if !same_generation(&before, &rustix::fs::fstat(&file).map_err(|_| malformed())?) {
                return Err(refused(69, "changed", entry.path));
            }
        }
        if bytes != entry.bytes {
            return Err(refused(64, "size", entry.path));
        }
        if !hash_matches(hasher, entry.hash) {
            return Err(refused(65, "sha256", entry.path));
        }
        if entry.kind != "L" {
            let executable =
                match rustix::fs::accessat(parent, *name, Access::EXEC_OK, AtFlags::EACCESS) {
                    Ok(()) => true,
                    Err(rustix::io::Errno::ACCESS | rustix::io::Errno::PERM) => false,
                    Err(_) => return Err(malformed()),
                };
            if executable != (entry.kind == "1") {
                return Err(refused(66, "mode", entry.path));
            }
        }
        if !same_generation(&before, &named(parent, name)?) {
            return Err(refused(69, "changed", entry.path));
        }
        // Pin and recheck each parent descriptor. A same-byte substitution
        // outside the granted root cannot become source-content evidence.
        for (index, child) in parents.iter().enumerate().rev() {
            let parent = index
                .checked_sub(1)
                .map_or(root, |previous| &parents[previous]);
            let current = named(parent, parts[index])?;
            if FileType::from_raw_mode(current.st_mode) != FileType::Directory
                || !same_inode(
                    &current,
                    &rustix::fs::fstat(child).map_err(|_| malformed())?,
                )
            {
                return Err(refused(63, "not_directory", entry.path));
            }
        }
        Ok(bytes)
    }

    pub(super) fn verify(path: &Path, entries: &[Entry<'_>], total: u64) -> Result<(), Failure> {
        // Only the explicitly selected root may be an alias (e.g. /tmp on
        // Darwin). Every component below it is descriptor-relative/no-follow.
        let resolved = path.canonicalize().map_err(|_| malformed())?;
        let root = rustix::fs::open(&resolved, directory_flags(), Mode::empty())
            .map_err(|_| malformed())?;
        let identity = rustix::fs::fstat(&root).map_err(|_| malformed())?;
        let check_root = || {
            let current = rustix::fs::stat(path).map_err(|_| malformed())?;
            if !same_inode(&identity, &current) {
                return Err(refused(69, "root_changed", ""));
            }
            Ok(())
        };
        check_root()?;
        let mut bytes = 0_u64;
        for entry in entries {
            bytes = bytes
                .checked_add(verify_entry(&root, entry)?)
                .ok_or_else(malformed)?;
        }
        check_root()?;
        if bytes != total {
            return Err(refused(68, "bytes", &bytes.to_string()));
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("source-verifier-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
    }

    fn row(path: &str, content: &[u8], kind: &str) -> String {
        use std::fmt::Write as _;
        let mut hash = String::new();
        for byte in Sha256::digest(content) {
            write!(hash, "{byte:02x}").unwrap();
        }
        format!("{hash}\t{}\t{kind}\t{path}\n", content.len())
    }

    #[test]
    fn verifies_binary_empty_executable_and_symlink_bytes_without_subprocesses() {
        let root = fixture();
        std::fs::create_dir(root.path().join("nested")).unwrap();
        let bytes: Vec<_> = (0..2 * 1024 * 1024).map(|n| (n % 256) as u8).collect();
        std::fs::write(root.path().join("nested/literal ' ; café.rs"), &bytes).unwrap();
        std::fs::write(root.path().join("empty"), b"").unwrap();
        std::fs::write(root.path().join("executable"), b"run").unwrap();
        for name in ["nested/literal ' ; café.rs", "empty"] {
            std::fs::set_permissions(
                root.path().join(name),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        std::fs::set_permissions(
            root.path().join("executable"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("../executable", root.path().join("nested/link")).unwrap();
        let manifest = row("nested/literal ' ; café.rs", &bytes, "0")
            + &row("empty", b"", "0")
            + &row("executable", b"run", "1")
            + &row("nested/link", b"../executable", "L");
        verify(root.path(), 4, bytes.len() as u64 + 16, manifest.as_bytes()).unwrap();
        symlink(root.path(), root.path().join("alias")).unwrap();
        verify(
            &root.path().join("alias"),
            4,
            bytes.len() as u64 + 16,
            manifest.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_each_integrity_failure_and_duplicate_or_truncated_manifests() {
        let root = fixture();
        std::fs::write(root.path().join("source"), b"source").unwrap();
        std::fs::set_permissions(
            root.path().join("source"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let valid = row("source", b"source", "0");
        for (manifest, count, total, code) in [
            (row("source", b"short", "0"), 1, 5, 64),
            (row("source", b"forged", "0"), 1, 6, 65),
            (row("source", b"source", "1"), 1, 6, 66),
            (row("missing", b"source", "0"), 1, 6, 63),
            (row("source", b"source", "L"), 1, 6, 63),
            (valid.clone(), 2, 6, 67),
            (valid.clone(), 1, 7, 68),
            (valid.trim_end().to_owned(), 1, 6, 67),
            (valid.clone() + &valid, 2, 12, 69),
            (row("../source", b"source", "0"), 1, 6, 62),
        ] {
            assert_eq!(
                verify(root.path(), count, total, manifest.as_bytes())
                    .unwrap_err()
                    .code,
                code,
                "{manifest:?}"
            );
        }
    }

    #[test]
    fn refuses_symlinked_ancestors_and_escaping_or_control_character_links() {
        let root = fixture();
        let other = fixture();
        std::fs::write(other.path().join("input"), b"same").unwrap();
        symlink(other.path(), root.path().join("parent")).unwrap();
        let manifest = row("parent/input", b"same", "0");
        let error = verify(root.path(), 1, 4, manifest.as_bytes()).unwrap_err();
        assert_eq!(error.code, 63);
        assert!(error.reason.starts_with("not_directory:"));
        for (name, target) in [
            ("escape", "../input"),
            ("absolute", "/input"),
            ("control", "input\n"),
            ("backslash", "dir\\input"),
        ] {
            symlink(target, root.path().join(name)).unwrap();
            let manifest = row(name, target.as_bytes(), "L");
            assert_eq!(
                verify(root.path(), 1, target.len() as u64, manifest.as_bytes())
                    .unwrap_err()
                    .code,
                63
            );
        }
    }

    #[test]
    fn bounds_untrusted_manifest_and_denominators_before_filesystem_access() {
        let root = fixture();
        assert_eq!(
            verify(root.path(), MAX_FILES + 1, 0, &b""[..])
                .unwrap_err()
                .code,
            69
        );
        assert_eq!(
            verify(root.path(), 0, MAX_BYTES + 1, &b""[..])
                .unwrap_err()
                .code,
            69
        );
        assert_eq!(
            verify(root.path(), 0, 0, std::io::repeat(b'x'))
                .unwrap_err()
                .reason,
            "manifest_limit"
        );
        verify(root.path(), 0, 0, &b""[..]).unwrap();
        for text in ["+1", "01", "-1", " 1", "18446744073709551616"] {
            assert!(parse_decimal(text).is_none());
        }
    }

    #[test]
    fn malformed_rows_never_authorize_filesystem_reads() {
        let root = fixture();
        let digest = "a".repeat(64);
        for manifest in [
            format!("{digest}\t0\t0\t\n"),
            format!("{digest}\t0\t0\t/absolute\n"),
            format!("{digest}\t0\t0\ta//b\n"),
            format!("{digest}\t0\t0\ta\\b\n"),
            format!("{digest}\t0\t0\t{}file\n", "a/".repeat(MAX_PATH_BYTES / 2)),
            format!("{digest}\t+0\t0\tfile\n"),
            format!("{digest}\t0\tX\tfile\n"),
            format!("{digest}\t0\t0\tfile\textra\n"),
            format!("{}\t0\t0\tfile\n", "A".repeat(64)),
        ] {
            let error = verify(root.path(), 1, 0, manifest.as_bytes()).unwrap_err();
            assert!(matches!(error.code, 62 | 69), "{manifest:?}: {error:?}");
        }
        assert_eq!(
            verify(root.path(), 1, 0, &b"\xff\n"[..]).unwrap_err().code,
            69
        );
    }

    #[test]
    fn fifo_is_refused_without_waiting_for_a_writer() {
        let root = fixture();
        #[cfg(target_vendor = "apple")]
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(root.path().join("pipe"))
                .status()
                .unwrap()
                .success()
        );
        #[cfg(not(target_vendor = "apple"))]
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.path().join("pipe"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let manifest = row("pipe", b"", "0");
        let started = std::time::Instant::now();
        assert_eq!(
            verify(root.path(), 1, 0, manifest.as_bytes())
                .unwrap_err()
                .code,
            63
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
