//! Exact final outputs from CMake's generated Unix Makefiles.
//!
//! CMake's `CreateLinkScript` adds `link.txt` as a prerequisite of the real
//! executable/library target. `WriteMakeRule` writes one prerequisite per
//! line, relative to the top-level build directory. Read that relationship,
//! never execute Make, parse arbitrary linker flags, or collect a build tree.
//! Utility/object targets without a link script add no output authority.
//!
//! This complements Ninja graph discovery without requiring the caller to
//! request a CMake File API codemodel or reconfigure an existing build.

#[cfg(unix)]
use anyhow::ensure;
use anyhow::{Context, Result};
#[cfg(unix)]
use std::collections::BTreeSet;
use std::path::Path;
#[cfg(unix)]
use std::path::{Component, PathBuf};

/// Compatibility reply required before invoking the worker-side query.
pub const PROBE_REPLY: &str = "rch-wkr cmake-outputs v1";
/// Framing distinguishes this listing from an unstructured command's stdout.
pub const OUTPUT_HEADER: &str = "RCH_CMAKE_MAKE_OUTPUTS_V1";
#[cfg(unix)]
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
#[cfg(unix)]
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_TARGETS: usize = 16_384;
#[cfg(unix)]
const MAX_PATH_BYTES: usize = 4096;

/// Synchronous worker entry point. Unsupported generators return the existing
/// absent-backend status (3); incomplete/unsafe metadata fails the query.
#[must_use]
pub fn main(arguments: &[String]) -> i32 {
    if arguments == ["probe"] {
        println!("{PROBE_REPLY}");
        return 0;
    }
    let [operation, directory] = arguments else {
        eprintln!("RCH_CMAKE_OUTPUTS_REFUSED: expected list <build-directory>");
        return 73;
    };
    if operation != "list" {
        eprintln!("RCH_CMAKE_OUTPUTS_REFUSED: unknown operation");
        return 73;
    }
    let result = std::env::current_dir()
        .context("resolve CMake query working directory")
        .and_then(|root| discover(&root, Path::new(directory)));
    match result {
        Ok(Some(listing)) => {
            // No bytes are exposed until every referenced metadata file and
            // the complete bounded output list have been validated.
            print!("{listing}");
            0
        }
        Ok(None) => 3,
        Err(error) => {
            eprintln!("RCH_CMAKE_OUTPUTS_REFUSED: {error:#}");
            73
        }
    }
}

/// Discover final regular-file outputs without changing the source/build tree.
///
/// Paths are relative to `root`, which is the already-owned project cwd.
/// Symlinked metadata and parent directories never grant output authority.
/// The existing artifact publisher continues to decide which returned files
/// may be published; in particular this query does not add symlink support.
///
/// # Errors
/// Fails on malformed, incomplete, oversized, substituted or escaping metadata.
#[cfg(unix)]
pub fn discover(root: &Path, directory: &Path) -> Result<Option<String>> {
    let directory = selected_directory(directory)?;
    let root = std::fs::canonicalize(root).context("resolve CMake project root")?;
    ensure!(root.is_dir(), "CMake project root is not a directory");
    let mut reader = MetadataReader::open(&root)?;
    let Some(cache) = reader.read(&directory.join("CMakeCache.txt"))? else {
        return Ok(None);
    };
    let generator = cache_value(&cache, "CMAKE_GENERATOR:INTERNAL=")?
        .filter(|value| !value.is_empty())
        .context("CMake cache has no generator")?;
    if generator != "Unix Makefiles" {
        return Ok(None);
    }
    let cache_root = cache_value(&cache, "CMAKE_CACHEFILE_DIR:INTERNAL=")?
        .context("CMake cache has no build directory")?;
    let cache_root = absolute_path(cache_root)?;
    ensure!(
        std::fs::canonicalize(&cache_root).context("resolve CMake cache directory")?
            == root.join(&directory),
        "CMake cache belongs to a different build directory"
    );
    let index = reader
        .read(&directory.join("CMakeFiles/TargetDirectories.txt"))?
        .context("CMake target directory index is missing")?;
    ensure!(
        index.is_empty() || index.ends_with('\n'),
        "incomplete CMake target directory index"
    );
    let mut targets = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut metadata = metadata_paths(&directory);
    for (index, target) in index.lines().enumerate() {
        ensure!(index < MAX_TARGETS, "too many CMake target directories");
        let target = absolute_path(target)?;
        let relative = target
            .strip_prefix(&cache_root)
            .or_else(|_| target.strip_prefix(root.join(&directory)))
            .context("CMake target directory is outside the selected build")?;
        let target = selected_directory(relative)?;
        ensure!(
            target
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".dir"))
                && target.parent().and_then(Path::file_name)
                    == Some(std::ffi::OsStr::new("CMakeFiles")),
            "invalid CMake target metadata directory"
        );
        ensure!(
            targets.insert(target.clone()),
            "duplicate CMake target directory"
        );
        let binary_directory = target
            .parent()
            .and_then(Path::parent)
            .context("CMake target has no binary directory")?;
        metadata.extend(metadata_paths(&directory.join(binary_directory)));
        let link = target.join("link.txt");
        let script = reader.read(&directory.join(&link))?;
        let makefile = reader.read(&directory.join(target).join("build.make"))?;
        // CMake indexes built-in utility targets without build.make/link.txt,
        // and object/custom targets have no link rule. Missing just one half
        // of an indexed linked target is incomplete metadata, not no output.
        let Some(makefile) = makefile else {
            ensure!(script.is_none(), "CMake linked target has no build.make");
            continue;
        };
        let output = linked_output(&makefile, &link)?;
        let Some(output) = output else {
            ensure!(
                script.is_none(),
                "CMake link script has no exact generated output rule"
            );
            continue;
        };
        let script = script.context("CMake linked target has no link script")?;
        ensure!(
            !script.is_empty() && script.ends_with('\n'),
            "incomplete CMake link script"
        );
        let output = resolve_output(&root, &directory, &cache_root, &output)?;
        outputs.insert(output);
    }
    ensure!(
        metadata.len() + outputs.len() <= MAX_TARGETS,
        "CMake output listing exceeds target limit"
    );
    ensure!(
        outputs
            .iter()
            .all(|output| !metadata.iter().any(|path| output.starts_with(path))),
        "CMake final output overlaps generated backend metadata"
    );
    let root_text = root.to_str().context("non-UTF-8 CMake project root")?;
    absolute_path(root_text)?;
    let mut listing = format!("{OUTPUT_HEADER}\n{root_text}\n{root_text}\n");
    for (output, rule) in metadata
        .into_iter()
        .map(|path| (path, "RERUN_CMAKE"))
        .chain(outputs.into_iter().map(|path| (path, "cmake_link")))
    {
        let path = root.join(output);
        let text = path.to_str().context("non-UTF-8 CMake output")?;
        ensure!(
            text.len() <= MAX_PATH_BYTES,
            "CMake output path is too long"
        );
        listing.push_str(text);
        listing.push_str(": ");
        listing.push_str(rule);
        listing.push('\n');
        ensure!(
            listing.len() <= MAX_OUTPUT_BYTES,
            "CMake output listing is too large"
        );
    }
    reader.revalidate()?;
    Ok(Some(listing))
}

#[cfg(unix)]
fn metadata_paths(directory: &Path) -> BTreeSet<PathBuf> {
    // These are CMake-owned backend names, not user output-directory globs.
    // Excluding the metadata directory itself also stops rsync descending
    // into it when the prior C++ policy includes a conventional build/** tree.
    [
        "CMakeCache.txt",
        "Makefile",
        "cmake_install.cmake",
        "CMakeFiles",
        ".cmake",
        "build.ninja",
    ]
    .into_iter()
    .map(|name| directory.join(name))
    .collect()
}

/// CMake Makefile metadata describes POSIX compiler outputs. A Windows worker
/// must not reinterpret these paths or make publication promises for them.
#[cfg(not(unix))]
pub fn discover(_root: &Path, _directory: &Path) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(unix)]
fn cache_value<'a>(cache: &'a str, prefix: &str) -> Result<Option<&'a str>> {
    ensure!(cache.ends_with('\n'), "incomplete CMake cache");
    let mut values = cache.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values.next();
    ensure!(values.next().is_none(), "duplicate CMake cache field");
    Ok(value)
}

#[cfg(unix)]
fn selected_directory(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().context("non-UTF-8 CMake metadata path")?;
    ensure!(
        text.len() <= MAX_PATH_BYTES
            && !text.chars().any(char::is_control)
            && !text.contains('\\')
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
        "CMake metadata directory must be a literal relative path"
    );
    Ok(path
        .components()
        .filter(|part| *part != Component::CurDir)
        .collect())
}

#[cfg(unix)]
fn absolute_path(text: &str) -> Result<PathBuf> {
    let path = Path::new(text);
    ensure!(
        path.is_absolute()
            && text.len() <= MAX_PATH_BYTES
            && !text.chars().any(char::is_control)
            && !text.contains('\\')
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "CMake metadata contains an invalid absolute path"
    );
    Ok(path.to_owned())
}

/// Decode exactly one Make word, not a shell word or an expression. CMake
/// escapes spaces and '#' in these rule paths. Unexpanded variables, patterns,
/// multiple prerequisites and continuation lines are never filenames here.
#[cfg(unix)]
fn make_word(value: &str) -> Option<String> {
    let mut result = String::new();
    let mut chars = value.trim_end_matches(' ').chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next()? {
                escaped @ (' ' | '#' | ':' | '\\') => result.push(escaped),
                _ => return None,
            },
            '$' | '%' | '#' | ':' | ';' | '=' | '|' => return None,
            ch if ch.is_whitespace() || ch.is_control() => return None,
            ch => result.push(ch),
        }
    }
    (!result.is_empty()).then_some(result)
}

#[cfg(unix)]
fn linked_output(makefile: &str, link: &Path) -> Result<Option<String>> {
    ensure!(
        makefile.starts_with("# CMAKE generated file: DO NOT EDIT!\n")
            && makefile.lines().any(|line| {
                line.starts_with("# Generated by \"Unix Makefiles\" Generator, CMake Version ")
            })
            && makefile.ends_with('\n'),
        "unsupported or incomplete CMake generated Makefile"
    );
    let mut selected = None;
    for line in makefile
        .lines()
        .filter(|line| !line.starts_with(['#', '\t']))
    {
        let Some((target, dependency)) = line.rsplit_once(": ") else {
            continue;
        };
        let Some(dependency) = make_word(dependency) else {
            continue;
        };
        if Path::new(&dependency) != link {
            continue;
        }
        let target = make_word(target).context("ambiguous CMake link target")?;
        ensure!(
            selected.replace(target).is_none(),
            "duplicate CMake link target rule"
        );
    }
    Ok(selected)
}

#[cfg(unix)]
fn resolve_output(
    root: &Path,
    directory: &Path,
    cache_root: &Path,
    output: &str,
) -> Result<PathBuf> {
    ensure!(
        !output.is_empty()
            && output.len() <= MAX_PATH_BYTES
            && !output.chars().any(char::is_control)
            && !output.contains('\\')
            && !output.ends_with('/'),
        "invalid CMake output path"
    );
    let output = Path::new(output);
    let (mut path, tail) = if output.is_absolute() {
        if let Ok(relative) = output.strip_prefix(root) {
            (PathBuf::new(), relative)
        } else {
            (
                directory.to_owned(),
                output
                    .strip_prefix(cache_root)
                    .context("CMake output leaves the project")?,
            )
        }
    } else {
        (directory.to_owned(), output)
    };
    let mut saw_name = false;
    for component in tail.components() {
        match component {
            Component::Normal(name) => {
                saw_name = true;
                path.push(name);
            }
            Component::CurDir => {}
            Component::ParentDir if !saw_name && path.pop() => {}
            _ => anyhow::bail!("CMake output has ambiguous or escaping ancestry"),
        }
    }
    ensure!(
        saw_name && !path.as_os_str().is_empty(),
        "CMake output is not a file"
    );
    Ok(path)
}

#[cfg(unix)]
struct MetadataReader {
    root: std::os::fd::OwnedFd,
    path: PathBuf,
    identity: rustix::fs::Stat,
    remaining: usize,
}

#[cfg(unix)]
impl MetadataReader {
    fn open(path: &Path) -> Result<Self> {
        use rustix::fs::{Mode, OFlags};
        let root = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let identity = rustix::fs::fstat(&root)?;
        Ok(Self {
            root,
            path: path.to_owned(),
            identity,
            remaining: MAX_METADATA_BYTES,
        })
    }

    fn revalidate(&self) -> Result<()> {
        let named = rustix::fs::statat(
            rustix::fs::CWD,
            &self.path,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        ensure!(
            named.st_dev == self.identity.st_dev && named.st_ino == self.identity.st_ino,
            "CMake project root changed during output discovery"
        );
        Ok(())
    }

    fn read(&mut self, path: &Path) -> Result<Option<String>> {
        use rustix::fs::{AtFlags, FileType, Mode, OFlags};
        use std::io::Read;
        self.revalidate()?;
        let path = selected_directory(path)?;
        let filename = path.file_name().context("metadata path has no filename")?;
        let mut parent = self.root.try_clone()?;
        for component in path
            .parent()
            .context("metadata path has no parent")?
            .components()
        {
            parent = match rustix::fs::openat(
                &parent,
                component.as_os_str(),
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(parent) => parent,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("open CMake metadata parent: {}", path.display())
                    });
                }
            };
        }
        let descriptor = match rustix::fs::openat(
            &parent,
            filename,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("open CMake metadata: {}", path.display()));
            }
        };
        let before = rustix::fs::fstat(&descriptor)?;
        ensure!(
            FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
            "CMake metadata is not a regular file: {}",
            path.display()
        );
        let budget = MAX_FILE_BYTES.min(self.remaining);
        ensure!(
            before.st_size >= 0 && u64::try_from(before.st_size)? <= budget as u64,
            "CMake metadata exceeds its read budget"
        );
        let mut text = String::new();
        let mut file = std::fs::File::from(descriptor);
        file.by_ref()
            .take((budget + 1) as u64)
            .read_to_string(&mut text)?;
        let after = rustix::fs::fstat(&file)?;
        let named = rustix::fs::statat(&parent, filename, AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            text.len() <= budget && same_file(&before, &after) && same_file(&after, &named),
            "CMake metadata changed during output discovery"
        );
        self.remaining -= text.len();
        Ok(Some(text))
    }
}

#[cfg(unix)]
fn same_file(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    const MAKE_HEADER: &str = "# CMAKE generated file: DO NOT EDIT!\n# Generated by \"Unix Makefiles\" Generator, CMake Version 3.31\n";

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let owner = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(owner.path()).unwrap();
        let build = root.join("cmake-build-debug");
        fs::create_dir_all(build.join("CMakeFiles/app.dir")).unwrap();
        fs::write(
            build.join("CMakeCache.txt"),
            format!(
                "CMAKE_GENERATOR:INTERNAL=Unix Makefiles\nCMAKE_CACHEFILE_DIR:INTERNAL={}\n",
                build.display()
            ),
        )
        .unwrap();
        fs::write(
            build.join("CMakeFiles/TargetDirectories.txt"),
            format!(
                "{}/CMakeFiles/app.dir\n{}/CMakeFiles/edit_cache.dir\n",
                build.display(),
                build.display()
            ),
        )
        .unwrap();
        fs::write(
            build.join("CMakeFiles/app.dir/link.txt"),
            "/usr/bin/cc object.o -o app\n",
        )
        .unwrap();
        fs::write(build.join("CMakeFiles/app.dir/build.make"), format!(
            "{MAKE_HEADER}app: CMakeFiles/app.dir/object.o\napp: CMakeFiles/app.dir/link.txt\n\t$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/app.dir/link.txt --verbose=$(VERBOSE)\n")).unwrap();
        (owner, root)
    }

    #[test]
    fn cmake_make_outputs_follow_generated_link_rules_without_executing_scripts() {
        let (_owner, root) = fixture();
        let build = root.join("cmake-build-debug");
        fs::write(root.join("source.c"), "unchanged source").unwrap();
        fs::write(
            build.join("CMakeFiles/app.dir/link.txt"),
            "touch should-not-exist\n",
        )
        .unwrap();
        let listing = discover(&root, Path::new("cmake-build-debug"))
            .unwrap()
            .unwrap();
        assert!(listing.starts_with(&format!(
            "{OUTPUT_HEADER}\n{root}\n{root}\n",
            root = root.display()
        )));
        assert!(listing.ends_with(&format!(
            "{}/cmake-build-debug/app: cmake_link\n",
            root.display()
        )));
        assert!(listing.contains(&format!(
            "{}/cmake-build-debug/CMakeFiles: RERUN_CMAKE\n",
            root.display()
        )));
        assert!(!root.join("should-not-exist").exists());
        assert!(!build.join("should-not-exist").exists());
        assert_eq!(
            fs::read_to_string(root.join("source.c")).unwrap(),
            "unchanged source"
        );
    }

    #[test]
    fn cmake_make_outputs_decode_literal_spaces_and_exact_sibling_outputs() {
        let (_owner, root) = fixture();
        let makefile = root.join("cmake-build-debug/CMakeFiles/app.dir/build.make");
        for (rule, expected) in [
            (
                "bin/app\\ with\\ spaces",
                "cmake-build-debug/bin/app with spaces",
            ),
            ("bin/app[debug]", "cmake-build-debug/bin/app[debug]"),
            ("../products/app", "products/app"),
            ("bin/app\\#name", "cmake-build-debug/bin/app#name"),
            ("x ", "cmake-build-debug/x"),
        ] {
            fs::write(
                &makefile,
                format!("{MAKE_HEADER}{rule}: CMakeFiles/app.dir/link.txt\n"),
            )
            .unwrap();
            let listing = discover(&root, Path::new("cmake-build-debug"))
                .unwrap()
                .unwrap();
            assert!(
                listing.ends_with(&format!("{}/{expected}: cmake_link\n", root.display())),
                "{listing}"
            );
        }
    }

    #[test]
    fn cmake_make_outputs_refuse_ambiguous_rules_and_escaping_outputs() {
        let (_owner, root) = fixture();
        let makefile = root.join("cmake-build-debug/CMakeFiles/app.dir/build.make");
        for rule in [
            "$(OUTPUT)",
            "first second",
            "%.o",
            "../../outside",
            "inside/../source.c",
            "/outside/app",
        ] {
            fs::write(
                &makefile,
                format!("{MAKE_HEADER}{rule}: CMakeFiles/app.dir/link.txt\n"),
            )
            .unwrap();
            assert!(
                discover(&root, Path::new("cmake-build-debug")).is_err(),
                "{rule}"
            );
        }
        for text in [
            "app: unrelated.txt\n".to_owned(),
            "app: CMakeFiles/app.dir/link.txt".to_owned(),
            "app: CMakeFiles/app.dir/link.txt\nother: CMakeFiles/app.dir/link.txt\n".to_owned(),
        ] {
            fs::write(&makefile, format!("{MAKE_HEADER}{text}")).unwrap();
            assert!(discover(&root, Path::new("cmake-build-debug")).is_err());
        }
    }

    #[test]
    fn cmake_make_outputs_refuse_symlinked_metadata_and_oversized_inputs() {
        for relative in [
            "CMakeCache.txt",
            "CMakeFiles/TargetDirectories.txt",
            "CMakeFiles/app.dir/link.txt",
            "CMakeFiles/app.dir/build.make",
            "CMakeFiles/app.dir",
        ] {
            let (_owner, root) = fixture();
            let path = root.join("cmake-build-debug").join(relative);
            let retained = path.with_extension("retained");
            fs::rename(&path, &retained).unwrap();
            symlink(&retained, &path).unwrap();
            assert!(
                discover(&root, Path::new("cmake-build-debug")).is_err(),
                "{relative}"
            );
            assert!(retained.exists());
        }
        let (_owner, root) = fixture();
        let path = root.join("cmake-build-debug/CMakeFiles/app.dir/link.txt");
        fs::write(&path, "x".repeat(MAX_FILE_BYTES + 1)).unwrap();
        assert!(discover(&root, Path::new("cmake-build-debug")).is_err());
    }

    #[test]
    fn cmake_make_outputs_distinguish_absent_backend_from_broken_owned_metadata() {
        let (_owner, root) = fixture();
        assert!(discover(&root, Path::new("missing")).unwrap().is_none());
        assert!(discover(&root, Path::new("../outside")).is_err());
        let build = root.join("cmake-build-debug");
        let link = build.join("CMakeFiles/app.dir/link.txt");
        let retained = link.with_extension("retained");
        fs::rename(&link, &retained).unwrap();
        assert!(discover(&root, Path::new("cmake-build-debug")).is_err());
        fs::rename(&retained, &link).unwrap();
        for cache in [
            "CMAKE_CACHEFILE_DIR:INTERNAL=/tmp/build\n",
            "CMAKE_GENERATOR:INTERNAL=\n",
            "CMAKE_GENERATOR:INTERNAL=Unix Makefiles",
            "CMAKE_GENERATOR:INTERNAL=Unix Makefiles\nCMAKE_GENERATOR:INTERNAL=Ninja\n",
        ] {
            fs::write(build.join("CMakeCache.txt"), cache).unwrap();
            assert!(discover(&root, Path::new("cmake-build-debug")).is_err());
        }
        for generator in ["Ninja", "Ninja Multi-Config", "Xcode"] {
            fs::write(
                build.join("CMakeCache.txt"),
                format!(
                    "CMAKE_GENERATOR:INTERNAL={generator}\nCMAKE_CACHEFILE_DIR:INTERNAL={}\n",
                    build.display()
                ),
            )
            .unwrap();
            assert!(
                discover(&root, Path::new("cmake-build-debug"))
                    .unwrap()
                    .is_none()
            );
        }
        fs::write(
            build.join("CMakeCache.txt"),
            format!(
                "CMAKE_GENERATOR:INTERNAL=Unix Makefiles\nCMAKE_CACHEFILE_DIR:INTERNAL={}\n",
                root.display()
            ),
        )
        .unwrap();
        assert!(discover(&root, Path::new("cmake-build-debug")).is_err());
    }

    #[test]
    fn real_cmake_makefiles_report_executable_static_and_shared_outputs_without_file_api() {
        if Command::new("cmake").arg("--version").output().is_err() {
            eprintln!("skipping real CMake output discovery: cmake is unavailable");
            return;
        }
        let owner = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(owner.path()).unwrap();
        fs::write(root.join("CMakeLists.txt"), concat!(
            "cmake_minimum_required(VERSION 3.20)\nproject(rch_outputs C)\n",
            "set(CMAKE_RUNTIME_OUTPUT_DIRECTORY \"${CMAKE_BINARY_DIR}/../products\")\n",
            "set(CMAKE_LIBRARY_OUTPUT_DIRECTORY \"${CMAKE_BINARY_DIR}/../products\")\n",
            "add_library(sample STATIC value.c)\nadd_library(shared SHARED value.c)\n",
            "add_executable(app main.c)\ntarget_link_libraries(app PRIVATE sample)\n",
            "add_custom_target(sidecar ALL COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_BINARY_DIR}/undeclared.txt)\n",
        )).unwrap();
        fs::write(root.join("value.c"), "int value(void) { return 37; }\n").unwrap();
        let source = "int value(void); int main(void) { return value() == 37 ? 0 : 1; }\n";
        fs::write(root.join("main.c"), source).unwrap();
        let configured = Command::new("cmake")
            .args(["-S", ".", "-B", "cmake-build-debug", "-G", "Unix Makefiles"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(configured.status.success(), "{configured:?}");
        let built = Command::new("cmake")
            .args(["--build", "cmake-build-debug", "--parallel", "1"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(built.status.success(), "{built:?}");
        assert!(!root.join("cmake-build-debug/.cmake/api/v1/reply").exists());
        let listing = discover(&root, Path::new("cmake-build-debug"))
            .unwrap()
            .unwrap();
        let outputs: BTreeSet<_> = listing
            .lines()
            .skip(3)
            .filter_map(|line| line.strip_suffix(": cmake_link").map(PathBuf::from))
            .collect();
        let shared = if cfg!(target_os = "macos") {
            "products/libshared.dylib"
        } else {
            "products/libshared.so"
        };
        assert_eq!(
            outputs,
            BTreeSet::from([
                root.join("products/app"),
                root.join("cmake-build-debug/libsample.a"),
                root.join(shared)
            ])
        );
        assert!(outputs.iter().all(|path| path.is_file()));
        assert!(
            Command::new(root.join("products/app"))
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(fs::read_to_string(root.join("main.c")).unwrap(), source);
        assert!(root.join("cmake-build-debug/undeclared.txt").exists());
    }
}
