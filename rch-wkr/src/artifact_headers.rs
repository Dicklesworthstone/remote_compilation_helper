//! Bounded executable-header observations for artifact platform preflight.
//!
//! Descend from held directory descriptors without following aliases below the
//! selected root. The sole exception is Cargo's explicit `target` alias, which
//! must resolve to the separately authorized target root. No response is emitted
//! until every file generation, traversed directory and selected root is checked.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde::de::{self, SeqAccess, Visitor};
use std::fmt;
use std::io::{Read, Write};

const PROBE_REPLY: &str = "rch-wkr artifact-headers v1";
const UNSAFE_EXIT: i32 = 73;
const MAX_CANDIDATES: usize = 16_384;
const MAX_PATH_BYTES: usize = 4_096;
// The caller serializes UTF-8 paths with serde_json. Even if every path byte
// needs quote/backslash escaping, the complete permitted candidate set and two
// filesystem-sized root names fit. Read through this cap rather than allocating
// a second copy of the complete request before parsing it.
const MAX_REQUEST_BYTES: u64 =
    (MAX_CANDIDATES * (2 * MAX_PATH_BYTES + 3) + 4 * MAX_PATH_BYTES + 16) as u64;
#[cfg(unix)]
const HEADER_BYTES: usize = 64;

#[derive(Debug, Deserialize)]
struct Request(
    String,
    Option<String>,
    #[serde(deserialize_with = "deserialize_paths")] Vec<String>,
);

type Headers = Vec<(String, Vec<u8>)>;

/// Called before the async runtime and optional logging sinks are initialized.
pub fn main(arguments: &[String]) -> i32 {
    match run(arguments, std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("RCH_ARTIFACT_HEADERS_UNSAFE {error:#}");
            UNSAFE_EXIT
        }
    }
}

fn run(arguments: &[String], input: impl Read, mut output: impl Write) -> Result<()> {
    ensure!(
        cfg!(unix),
        "descriptor-relative artifact probes require Unix"
    );
    match arguments {
        [operation] if operation == "probe" => writeln!(output, "{PROBE_REPLY}")?,
        [operation] if operation == "inspect" => {
            let request = read_request(input, MAX_REQUEST_BYTES)?;
            let headers = inspect(&request)?;
            serde_json::to_writer(&mut output, &headers).context("write artifact headers")?;
            writeln!(output)?;
        }
        _ => anyhow::bail!("expected probe or inspect"),
    }
    Ok(())
}

fn read_request(input: impl Read, maximum: u64) -> Result<Request> {
    let mut input = input.take(
        maximum
            .checked_add(1)
            .context("request byte limit overflow")?,
    );
    let request = serde_json::from_reader(&mut input).context("read artifact header request")?;
    ensure!(
        input.limit() != 0,
        "artifact header request exceeds byte limit"
    );
    Ok(request)
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= MAX_PATH_BYTES
            && !path.starts_with('/')
            && !path.chars().any(char::is_control)
            && path.split('/').all(|part| !matches!(part, "" | "." | "..")),
        "artifact path is not a bounded literal relative path"
    );
    Ok(())
}

fn deserialize_paths<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    struct Paths;

    impl<'de> Visitor<'de> for Paths {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded array of literal relative artifact paths")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut paths = Vec::new();
            while let Some(path) = sequence.next_element::<String>()? {
                if paths.len() == MAX_CANDIDATES {
                    return Err(de::Error::custom("too many artifact header candidates"));
                }
                validate_path(&path).map_err(de::Error::custom)?;
                paths.push(path);
            }
            Ok(paths)
        }
    }

    deserializer.deserialize_seq(Paths)
}

#[cfg(unix)]
fn inspect(request: &Request) -> Result<Headers> {
    unix::inspect_with(request, |_, _| Ok(()))
}

#[cfg(not(unix))]
fn inspect(request: &Request) -> Result<Headers> {
    let _ = (&request.0, &request.1, &request.2);
    anyhow::bail!("descriptor-relative artifact probes require Unix")
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
    use std::fs::File;
    use std::path::Path;

    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY);

    /// Tests arrange real replacements at these observation boundaries. The
    /// production closure does nothing; there is no configurable runtime hook.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Observation {
        BeforeRead,
        AfterRead,
        BeforeResponse,
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn same_generation(left: &Stat, right: &Stat) -> bool {
        same_inode(left, right)
            && left.st_mode == right.st_mode
            && left.st_nlink == right.st_nlink
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    struct Root<'a> {
        name: &'a Path,
        descriptor: OwnedFd,
    }

    impl<'a> Root<'a> {
        fn open(name: &'a str) -> Result<Self> {
            let name = Path::new(name);
            // Root aliases such as Darwin's /tmp are permitted. Pin the
            // resolved directory, then check the caller's original spelling.
            let resolved = name.canonicalize().context("resolve artifact probe root")?;
            let descriptor = rustix::fs::open(&resolved, DIRECTORY_FLAGS, Mode::empty())
                .context("open artifact probe root")?;
            let root = Self { name, descriptor };
            root.verify()
                .context("artifact probe root changed while opening")?;
            Ok(root)
        }

        fn verify(&self) -> Result<()> {
            ensure!(
                same_inode(
                    &rustix::fs::fstat(&self.descriptor)?,
                    &rustix::fs::stat(self.name)?,
                ),
                "artifact probe root changed before response"
            );
            Ok(())
        }
    }

    fn verify_target_alias(root: &Root<'_>, target: &Root<'_>) -> Result<()> {
        ensure!(
            same_inode(
                &rustix::fs::statat(&root.descriptor, "target", AtFlags::empty())?,
                &rustix::fs::fstat(&target.descriptor)?,
            ),
            "target alias has a different authorized root"
        );
        Ok(())
    }

    pub(super) fn inspect_with(
        request: &Request,
        mut observe: impl FnMut(Observation, &str) -> Result<()>,
    ) -> Result<Headers> {
        // Keep validation at the filesystem entry point as well as during
        // decoding, so no future internal caller can bypass the input bounds.
        ensure!(
            request.2.len() <= MAX_CANDIDATES,
            "too many artifact header candidates"
        );
        for path in &request.2 {
            validate_path(path)?;
        }
        let root = Root::open(&request.0)?;
        let mut target = None;
        let mut result = Vec::with_capacity(request.2.len());
        for path in &request.2 {
            let components: Vec<_> = path.split('/').collect();
            let mut parts = components.as_slice();
            let target_alias = parts[0] == "target"
                && parts.len() > 1
                && FileType::from_raw_mode(
                    rustix::fs::statat(&root.descriptor, "target", AtFlags::SYMLINK_NOFOLLOW)?
                        .st_mode,
                ) == FileType::Symlink;
            let first = if target_alias {
                if target.is_none() {
                    let name = request
                        .1
                        .as_deref()
                        .context("target alias has no authorized root")?;
                    target = Some(Root::open(name)?);
                }
                let target = target
                    .as_ref()
                    .context("missing authorized target descriptor")?;
                verify_target_alias(&root, target)?;
                parts = &parts[1..];
                target.descriptor.try_clone()?
            } else {
                root.descriptor.try_clone()?
            };

            let mut directories = vec![first];
            for part in &parts[..parts.len() - 1] {
                let parent = directories
                    .last()
                    .context("missing artifact parent descriptor")?;
                let next = rustix::fs::openat(parent, *part, DIRECTORY_FLAGS, Mode::empty())
                    .context("open artifact directory without following links")?;
                directories.push(next);
            }
            let directory = directories
                .last()
                .context("missing artifact parent descriptor")?;
            let name = parts[parts.len() - 1];
            let descriptor = rustix::fs::openat(directory, name, FILE_FLAGS, Mode::empty())
                .context("open artifact header without following links")?;
            let mut file = File::from(descriptor);
            let before = rustix::fs::fstat(&file).context("inspect artifact header")?;
            ensure!(
                FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
                "artifact header is not a regular file"
            );
            let wanted = u64::try_from(before.st_size)
                .context("negative artifact size")?
                .min(HEADER_BYTES as u64) as usize;
            let mut prefix = vec![0; wanted];
            observe(Observation::BeforeRead, path)?;
            file.read_exact(&mut prefix)
                .context("artifact header was truncated while reading")?;
            observe(Observation::AfterRead, path)?;
            let after = rustix::fs::fstat(&file)?;
            let named = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
            ensure!(
                same_generation(&before, &after) && same_generation(&after, &named),
                "artifact changed while reading its header"
            );
            for (edge, name) in directories.windows(2).zip(parts).rev() {
                ensure!(
                    same_inode(
                        &rustix::fs::statat(&edge[0], *name, AtFlags::SYMLINK_NOFOLLOW)?,
                        &rustix::fs::fstat(&edge[1])?,
                    ),
                    "artifact directory changed while reading its header"
                );
            }
            if target_alias {
                verify_target_alias(
                    &root,
                    target
                        .as_ref()
                        .context("missing authorized target descriptor")?,
                )?;
            }
            result.push((path.clone(), prefix));
        }
        observe(Observation::BeforeResponse, "")?;
        root.verify()?;
        if let Some(target) = target {
            target
                .verify()
                .context("authorized target root changed before response")?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_requires_exact_shape_literal_paths_and_finite_candidate_count() {
        for input in [
            "null",
            "{}",
            "[\"/root\",null]",
            "[\"/root\",null,[],0]",
            "[\"/root\",false,[]]",
            "[\"/root\",null,[1]]",
            "[\"/root\",null,[]] trailing",
        ] {
            assert!(
                read_request(input.as_bytes(), MAX_REQUEST_BYTES).is_err(),
                "{input}"
            );
        }
        for path in [
            "",
            "/absolute",
            "../escape",
            "a/../b",
            "a//b",
            "a/",
            "./a",
            "a/./b",
            "a\nb",
            "a\u{0085}b",
        ] {
            let input = serde_json::to_vec(&("/root", None::<&str>, [path])).unwrap();
            assert!(
                read_request(input.as_slice(), MAX_REQUEST_BYTES).is_err(),
                "{path:?}"
            );
        }
        for (path, accepted) in [
            ("é".repeat(MAX_PATH_BYTES / 2), true),
            ("é".repeat(MAX_PATH_BYTES / 2 + 1), false),
        ] {
            let input = serde_json::to_vec(&("/root", None::<&str>, [path])).unwrap();
            assert_eq!(
                read_request(input.as_slice(), MAX_REQUEST_BYTES).is_ok(),
                accepted
            );
        }
        for (count, accepted) in [(MAX_CANDIDATES, true), (MAX_CANDIDATES + 1, false)] {
            let input = serde_json::to_vec(&("/root", None::<&str>, vec!["a"; count])).unwrap();
            assert_eq!(
                read_request(input.as_slice(), MAX_REQUEST_BYTES).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn request_budget_includes_trailing_whitespace_and_all_escaped_bytes() {
        let input = br#"["/root",null,["quote\"-backslash\\"]]"#;
        let exact = input.len() as u64;
        assert!(read_request(input.as_slice(), exact).is_ok());
        assert!(read_request(input.as_slice(), exact - 1).is_err());
        let padded = [input.as_slice(), b" "].concat();
        assert!(read_request(padded.as_slice(), exact).is_err());
    }

    #[cfg(unix)]
    mod filesystem {
        use super::*;
        use crate::artifact_headers::unix::{Observation, inspect_with};
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::path::Path;

        fn request(root: &Path, target: Option<&Path>, paths: &[&str]) -> Request {
            Request(
                root.to_str().unwrap().to_owned(),
                target.map(|path| path.to_str().unwrap().to_owned()),
                paths.iter().map(|path| (*path).to_owned()).collect(),
            )
        }

        fn wire(request: &Request) -> Vec<u8> {
            serde_json::to_vec(&(&request.0, &request.1, &request.2)).unwrap()
        }

        #[test]
        fn reads_only_prefixes_preserving_order_duplicates_and_opaque_path_bytes() {
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().join("source");
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("bin")).unwrap();
            let bytes: Vec<u8> = (0..=255).collect();
            fs::write(root.join("bin/é 'quote\"\\file"), &bytes).unwrap();
            fs::write(root.join("empty"), b"").unwrap();
            fs::write(root.join("short"), b"\x7fELF\0").unwrap();
            let paths = ["short", "bin/é 'quote\"\\file", "empty", "short"];
            let request = request(&root, None, &paths);
            let expected = vec![
                (paths[0].to_owned(), b"\x7fELF\0".to_vec()),
                (paths[1].to_owned(), bytes[..HEADER_BYTES].to_vec()),
                (paths[2].to_owned(), Vec::new()),
                (paths[3].to_owned(), b"\x7fELF\0".to_vec()),
            ];
            assert_eq!(inspect(&request).unwrap(), expected);
            let mut output = Vec::new();
            run(&["inspect".into()], wire(&request).as_slice(), &mut output).unwrap();
            assert_eq!(
                serde_json::from_slice::<Headers>(&output).unwrap(),
                expected
            );
            assert!(output.ends_with(b"\n"));
        }

        #[test]
        fn accepts_root_alias_and_only_the_explicitly_authorized_target_alias() {
            let owner = tempfile::tempdir().unwrap();
            let source = owner.path().join("source");
            let root = owner.path().join("root-alias");
            let target = owner.path().join("pooled-target");
            let target_name = owner.path().join("target-alias");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&target).unwrap();
            fs::create_dir(target.join("debug")).unwrap();
            fs::write(target.join("debug/app"), b"MachO").unwrap();
            symlink(&source, &root).unwrap();
            symlink(&target, &target_name).unwrap();
            symlink(&target, source.join("target")).unwrap();
            let paths = ["target/debug/app"];
            assert_eq!(
                inspect(&request(&root, Some(&target_name), &paths)).unwrap(),
                vec![(paths[0].to_owned(), b"MachO".to_vec())]
            );
            assert!(inspect(&request(&root, None, &paths)).is_err());
            assert!(inspect(&request(&root, Some(&source), &paths)).is_err());
            assert!(inspect(&request(&root, Some(&target), &["target"])).is_err());
        }

        #[test]
        fn ordinary_target_directory_does_not_use_an_unneeded_authorized_root() {
            let owner = tempfile::tempdir().unwrap();
            fs::create_dir(owner.path().join("target")).unwrap();
            fs::write(owner.path().join("target/app"), b"PE").unwrap();
            let absent = owner.path().join("unused");
            assert_eq!(
                inspect(&request(owner.path(), Some(&absent), &["target/app"])).unwrap(),
                vec![("target/app".to_owned(), b"PE".to_vec())]
            );
        }

        #[test]
        fn refuses_symlinked_ancestors_and_files_special_entries_and_partial_results() {
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().join("root");
            let other = owner.path().join("other");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&other).unwrap();
            fs::write(root.join("good"), b"ELF").unwrap();
            fs::write(other.join("app"), b"foreign").unwrap();
            symlink(&other, root.join("alias")).unwrap();
            symlink(other.join("app"), root.join("linked-file")).unwrap();
            // rustix does not expose mknodat/mkfifoat on Darwin. Keep the
            // same real FIFO refusal case using the native system utility.
            #[cfg(target_vendor = "apple")]
            assert!(
                std::process::Command::new("/usr/bin/mkfifo")
                    .arg(root.join("fifo"))
                    .status()
                    .unwrap()
                    .success()
            );
            #[cfg(not(target_vendor = "apple"))]
            rustix::fs::mknodat(
                rustix::fs::CWD,
                root.join("fifo"),
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                0,
            )
            .unwrap();
            fs::create_dir(root.join("directory")).unwrap();
            for path in ["alias/app", "linked-file", "fifo", "directory", "missing"] {
                let request = request(&root, None, &["good", path]);
                let mut output = Vec::new();
                assert!(
                    run(&["inspect".into()], wire(&request).as_slice(), &mut output).is_err(),
                    "{path}"
                );
                assert!(
                    output.is_empty(),
                    "failed probes must not expose a partial header list"
                );
            }
        }

        #[test]
        fn rejects_file_replacement_truncation_and_metadata_mutation_during_read() {
            for mutation in ["replace", "truncate", "mode", "links", "contents"] {
                let owner = tempfile::tempdir().unwrap();
                let path = owner.path().join("app");
                fs::write(&path, [7_u8; HEADER_BYTES + 1]).unwrap();
                let request = request(owner.path(), None, &["app"]);
                let result = inspect_with(&request, |step, _| {
                    let selected = if mutation == "truncate" {
                        Observation::BeforeRead
                    } else {
                        Observation::AfterRead
                    };
                    if step != selected {
                        return Ok(());
                    }
                    match mutation {
                        "replace" => {
                            fs::rename(&path, owner.path().join("old-app"))?;
                            fs::write(&path, [7_u8; HEADER_BYTES + 1])?;
                        }
                        "truncate" => fs::OpenOptions::new().write(true).open(&path)?.set_len(0)?,
                        "mode" => {
                            let mode = fs::metadata(&path)?.permissions().mode();
                            fs::set_permissions(&path, fs::Permissions::from_mode(mode ^ 0o100))?;
                        }
                        "links" => fs::hard_link(&path, owner.path().join("extra-link"))?,
                        "contents" => {
                            fs::write(&path, [8_u8; HEADER_BYTES + 1])?;
                            fs::File::open(&path)?.set_modified(std::time::UNIX_EPOCH)?;
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                });
                assert!(result.is_err(), "accepted concurrent {mutation}");
            }
        }

        #[test]
        fn refuses_replaced_ancestor_and_retargeted_cargo_alias() {
            let owner = tempfile::tempdir().unwrap();
            let root = owner.path().join("root");
            fs::create_dir_all(root.join("target/debug")).unwrap();
            fs::write(root.join("target/debug/app"), b"old").unwrap();
            let ordinary_request = request(&root, None, &["target/debug/app"]);
            assert!(
                inspect_with(&ordinary_request, |step, _| {
                    if step == Observation::AfterRead {
                        fs::rename(root.join("target/debug"), root.join("old-debug"))?;
                        fs::create_dir(root.join("target/debug"))?;
                    }
                    Ok(())
                })
                .is_err()
            );

            let alias_root = owner.path().join("alias-root");
            let authorized = owner.path().join("authorized");
            let foreign = owner.path().join("foreign");
            fs::create_dir(&alias_root).unwrap();
            fs::create_dir(&authorized).unwrap();
            fs::create_dir(&foreign).unwrap();
            fs::write(authorized.join("app"), b"old").unwrap();
            symlink(&authorized, alias_root.join("target")).unwrap();
            let request = request(&alias_root, Some(&authorized), &["target/app"]);
            assert!(
                inspect_with(&request, |step, _| {
                    if step == Observation::AfterRead {
                        fs::rename(alias_root.join("target"), alias_root.join("old-target"))?;
                        symlink(&foreign, alias_root.join("target"))?;
                    }
                    Ok(())
                })
                .is_err()
            );
        }

        #[test]
        fn rechecks_both_root_names_before_emitting_a_response() {
            for replace_target in [false, true] {
                let owner = tempfile::tempdir().unwrap();
                let root = owner.path().join("root");
                let target = owner.path().join("target");
                fs::create_dir(&root).unwrap();
                fs::create_dir(&target).unwrap();
                fs::write(target.join("app"), b"prefix").unwrap();
                symlink(&target, root.join("target")).unwrap();
                let request = request(&root, Some(&target), &["target/app"]);
                assert!(
                    inspect_with(&request, |step, _| {
                        if step == Observation::BeforeResponse {
                            let replaced = if replace_target { &target } else { &root };
                            fs::rename(replaced, owner.path().join("retained-old-root"))?;
                            fs::create_dir(replaced)?;
                        }
                        Ok(())
                    })
                    .is_err(),
                    "accepted root replacement: target={replace_target}"
                );
            }
        }

        #[test]
        fn unrelated_sibling_changes_do_not_invalidate_held_directories() {
            let owner = tempfile::tempdir().unwrap();
            fs::create_dir(owner.path().join("bin")).unwrap();
            fs::write(owner.path().join("bin/app"), b"prefix").unwrap();
            let request = request(owner.path(), None, &["bin/app"]);
            assert_eq!(
                inspect_with(&request, |step, _| {
                    if step == Observation::AfterRead {
                        fs::write(owner.path().join("bin/unrelated"), b"new")?;
                    }
                    Ok(())
                })
                .unwrap(),
                vec![("bin/app".to_owned(), b"prefix".to_vec())]
            );
        }

        #[test]
        fn capability_and_empty_inventory_have_exact_stdout_and_reject_extra_arguments() {
            let mut output = Vec::new();
            run(&["probe".into()], &b"ignored"[..], &mut output).unwrap();
            assert_eq!(output, b"rch-wkr artifact-headers v1\n");
            let owner = tempfile::tempdir().unwrap();
            let request = request(owner.path(), None, &[]);
            let mut output = Vec::new();
            run(&["inspect".into()], wire(&request).as_slice(), &mut output).unwrap();
            assert_eq!(output, b"[]\n");
            for arguments in [
                vec![],
                vec!["probe".into(), "extra".into()],
                vec!["inspect".into(), "extra".into()],
                vec!["unknown".into()],
            ] {
                assert!(run(&arguments, &b""[..], Vec::new()).is_err());
            }
        }
    }
}
