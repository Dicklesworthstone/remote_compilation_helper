//! Create-only worker source topology and its read-only diagnostic protocol.
//!
//! The registry owns admission, locking and durability. This operation only
//! observes or establishes the requested path mapping: it never replaces an
//! existing name, repairs permissions, or grants source ownership. All path
//! resolution and JSON encoding happen in the deployed Rust worker.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

/// Capability reply required by the shell adapter before any path operation.
pub const PROBE_REPLY: &str = "rch-wkr source-namespace-paths v1";
/// A create operation could not establish the requested namespace.
pub const REFUSAL_EXIT: i32 = 73;
const REPORT_PREFIX: &str = "RCH_SOURCE_TOPOLOGY_CHECK_V1 ";
const MAX_REPORT_BYTES: usize = 65_535;
const MAX_PATH_BYTES: usize = 4096;
const MAX_SYMLINKS: usize = 40;
const MAX_COMPONENTS: usize = 4096;

/// Add the shared worker locator to either packaged copy of the shell adapter.
pub fn shell_script(adapter: &str) -> String {
    format!("{}\n{adapter}", crate::wkr_locate::WKR_LOCATE_SHELL)
}

/// Synchronous worker entry point; it needs neither a runtime nor logging.
pub fn main(arguments: &[String]) -> i32 {
    run(
        arguments,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

/// Execute the worker protocol using explicit output streams.
pub fn run(arguments: &[String], stdout: &mut impl Write, stderr: &mut impl Write) -> i32 {
    if arguments.len() == 1 && arguments[0] == "probe" {
        return if writeln!(stdout, "{PROBE_REPLY}").is_ok() {
            0
        } else {
            REFUSAL_EXIT
        };
    }
    let (mode, canonical, alias, report) = match arguments {
        [mode, canonical, alias] if matches!(mode.as_str(), "check" | "create") => {
            (mode.as_str(), canonical.as_str(), alias.as_str(), false)
        }
        [mode, canonical, alias, option] if mode == "check" && option == "--report-json" => {
            (mode.as_str(), canonical.as_str(), alias.as_str(), true)
        }
        _ => return REFUSAL_EXIT,
    };
    let topology = crate::SourceTopology {
        canonical_root: canonical.to_owned(),
        alias_root: alias.to_owned(),
    };
    if topology.validate().is_err() {
        return refuse(stderr, "invalid namespace paths");
    }
    if mode == "check" {
        if report {
            report_check(canonical, alias, stdout)
        } else {
            i32::from(!namespace_matches(Path::new(canonical), Path::new(alias)))
        }
    } else {
        create_namespace(Path::new(canonical), Path::new(alias), stderr)
    }
}

fn refuse(stderr: &mut impl Write, reason: &str) -> i32 {
    let _ = writeln!(stderr, "RCH: source namespace: {reason}");
    REFUSAL_EXIT
}

fn invalid_path(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Resolve existing links while preserving missing suffixes, like realpath -m.
/// A dangling correctly targeted alias must compare equal before the canonical
/// directory is created. Links are expanded before `..`, and both expansion and
/// result sizes are bounded. No executable from PATH participates in authority.
fn resolve_missing(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid_path("namespace path is not absolute"));
    }
    let mut pending: VecDeque<OsString> = path
        .components()
        .map(|part| part.as_os_str().to_owned())
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    let mut components = 0;
    while let Some(part) = pending.pop_front() {
        components += 1;
        if components > MAX_COMPONENTS {
            return Err(invalid_path("namespace resolution component limit"));
        }
        let component = Path::new(&part)
            .components()
            .next()
            .ok_or_else(|| invalid_path("empty namespace component"))?;
        match component {
            Component::RootDir => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(_) => {
                let candidate = resolved.join(&part);
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.is_symlink() => {
                        links += 1;
                        if links > MAX_SYMLINKS {
                            return Err(invalid_path("namespace resolution symlink limit"));
                        }
                        let target = fs::read_link(&candidate)?;
                        for part in target.components().rev() {
                            pending.push_front(part.as_os_str().to_owned());
                        }
                    }
                    Ok(_) => resolved.push(part),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                        ) =>
                    {
                        resolved.push(part);
                    }
                    Err(error) => return Err(error),
                }
            }
            Component::Prefix(_) => {
                return Err(invalid_path("unsupported namespace path prefix"));
            }
        }
        if resolved.as_os_str().len() > MAX_PATH_BYTES
            || pending.len().saturating_add(components) > MAX_COMPONENTS
        {
            return Err(invalid_path("namespace resolution size limit"));
        }
    }
    let text = resolved
        .to_str()
        .ok_or_else(|| invalid_path("namespace target is not UTF-8"))?;
    if !resolved.is_absolute() || text.contains(['\0', '\n', '\r']) {
        return Err(invalid_path("ambiguous namespace target"));
    }
    Ok(resolved)
}

fn namespace_matches(canonical: &Path, alias: &Path) -> bool {
    if !canonical.is_dir() || !alias.is_dir() {
        return false;
    }
    match (resolve_missing(canonical), resolve_missing(alias)) {
        (Ok(canonical), Ok(alias)) => canonical == alias,
        _ => false,
    }
}

fn directory_state(path: &Path) -> &'static str {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => "directory",
        Ok(_) => "not_directory",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => "unavailable",
    }
}

fn physical_text(path: &Path) -> Option<String> {
    resolve_missing(path)
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
}

fn ascii_json(value: &impl serde::Serialize) -> serde_json::Result<String> {
    let serialized = serde_json::to_string(value)?;
    let mut escaped = String::with_capacity(serialized.len());
    for character in serialized.chars() {
        if character.is_ascii() {
            escaped.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                // Formatting into a String cannot fail.
                let _ = write!(escaped, "\\u{unit:04x}");
            }
        }
    }
    Ok(escaped)
}

fn report_check(canonical: &str, alias: &str, stdout: &mut impl Write) -> i32 {
    let checked = namespace_matches(Path::new(canonical), Path::new(alias));
    let canonical_physical = physical_text(Path::new(canonical));
    let alias_physical = physical_text(Path::new(alias));
    let canonical_state = directory_state(Path::new(canonical));
    let alias_state = directory_state(Path::new(alias));
    let outcome = match (canonical_state, alias_state) {
        ("unavailable", _) | (_, "unavailable") => "unavailable",
        ("missing", _) => "canonical_missing",
        ("not_directory", _) => "canonical_not_directory",
        (_, "missing") => "alias_missing",
        (_, "not_directory") => "alias_not_directory",
        _ => match (&canonical_physical, &alias_physical) {
            (Some(canonical), Some(alias)) if canonical != alias => "conflicting_alias_base",
            (Some(_), Some(_)) if checked => "compatible",
            _ => "unavailable",
        },
    };
    let report = serde_json::json!({
        "canonical": canonical,
        "alias": alias,
        "canonical_physical": canonical_physical,
        "alias_physical": alias_physical,
        "outcome": outcome,
    });
    let Ok(encoded) = ascii_json(&report) else {
        return 2;
    };
    if REPORT_PREFIX.len() + encoded.len() > MAX_REPORT_BYTES
        || writeln!(stdout, "{REPORT_PREFIX}{encoded}").is_err()
    {
        return 2;
    }
    match outcome {
        "compatible" => 0,
        "unavailable" => 2,
        _ => 1,
    }
}

#[cfg(unix)]
fn incompatible(
    canonical: &Path,
    alias: &Path,
    code: &str,
    reason: &str,
    stderr: &mut impl Write,
) -> i32 {
    let _ = writeln!(stderr, "RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: {code}");
    let mapping = serde_json::json!({
        "canonical": canonical,
        "canonical_physical": physical_text(canonical).as_deref().unwrap_or("<unresolved>"),
        "alias": alias,
        "alias_physical": physical_text(alias).as_deref().unwrap_or("<unresolved>"),
    });
    if let Ok(encoded) = ascii_json(&mapping)
        && encoded.len() <= MAX_REPORT_BYTES
    {
        let _ = writeln!(stderr, "RCH_SOURCE_TOPOLOGY_PATHS {encoded}");
    } else {
        let _ = writeln!(
            stderr,
            "RCH: source namespace: physical mapping diagnostic unavailable"
        );
    }
    refuse(stderr, reason)
}

#[cfg(unix)]
fn absent(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn create_namespace(canonical: &Path, alias: &Path, stderr: &mut impl Write) -> i32 {
    use std::os::unix::fs::symlink;

    // Restore only an absent name next to a valid symlink. An alias directory
    // may contain unrelated work and must never become the canonical target.
    if absent(canonical).unwrap_or(false)
        && fs::symlink_metadata(alias).is_ok_and(|metadata| metadata.is_symlink())
        && alias.is_dir()
    {
        let Ok(physical) = resolve_missing(alias) else {
            return refuse(stderr, "unresolvable alias base");
        };
        if !canonical.starts_with(&physical) {
            if let Some(parent) = canonical.parent() {
                let _ = fs::create_dir_all(parent);
            }
            // symlink(2) is create-only, even when a competing initializer
            // placed a directory at the name. It cannot create a nested link.
            let _ = symlink(physical, canonical);
        }
    }

    match absent(alias) {
        Ok(false) => {
            let Ok(canonical_physical) = resolve_missing(canonical) else {
                return refuse(stderr, "unresolvable canonical base");
            };
            let Ok(alias_physical) = resolve_missing(alias) else {
                return refuse(stderr, "unresolvable alias base");
            };
            if canonical_physical != alias_physical {
                return incompatible(
                    canonical,
                    alias,
                    "conflicting_alias_base",
                    "conflicting alias base",
                    stderr,
                );
            }
        }
        Ok(true) => {}
        Err(_) => return refuse(stderr, "unresolvable alias base"),
    }
    match absent(canonical) {
        Ok(true) if fs::create_dir_all(canonical).is_err() => {
            return refuse(stderr, "cannot create canonical base");
        }
        Err(_) => return refuse(stderr, "unresolvable canonical base"),
        _ => {}
    }
    if !canonical.is_dir() {
        return incompatible(
            canonical,
            alias,
            "canonical_not_directory",
            "canonical base is not a directory",
            stderr,
        );
    }
    // A directory may be reached through an ambiguous or unresolvable link.
    // Refuse before creating the alias, so a failed check leaves no new name.
    if resolve_missing(canonical).is_err() {
        return refuse(stderr, "unresolvable canonical base");
    }
    match absent(alias) {
        Ok(true) if symlink(canonical, alias).is_err() && !namespace_matches(canonical, alias) => {
            return refuse(stderr, "cannot create alias base");
        }
        Err(_) => return refuse(stderr, "unresolvable alias base"),
        _ => {}
    }
    if namespace_matches(canonical, alias) {
        // Only the registry may acknowledge readiness after its own barriers.
        0
    } else {
        refuse(stderr, "namespace changed during initialization")
    }
}

#[cfg(not(unix))]
fn create_namespace(_canonical: &Path, _alias: &Path, stderr: &mut impl Write) -> i32 {
    refuse(stderr, "source namespace creation requires a Unix worker")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, symlink};

    fn execute(mode: &str, canonical: &Path, alias: &Path, report: bool) -> (i32, String, String) {
        let mut arguments = vec![
            mode.to_owned(),
            canonical.to_str().unwrap().to_owned(),
            alias.to_str().unwrap().to_owned(),
        ];
        if report {
            arguments.push("--report-json".into());
        }
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let status = run(&arguments, &mut stdout, &mut stderr);
        (
            status,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    fn report(canonical: &Path, alias: &Path, expected: &str) -> serde_json::Value {
        let (status, stdout, stderr) = execute("check", canonical, alias, true);
        assert_eq!(
            status,
            if expected == "compatible" {
                0
            } else if expected == "unavailable" {
                2
            } else {
                1
            }
        );
        assert!(stderr.is_empty(), "{stderr}");
        assert!(stdout.is_ascii());
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.len() <= MAX_REPORT_BYTES + 1);
        let result: serde_json::Value =
            serde_json::from_str(stdout.strip_prefix(REPORT_PREFIX).unwrap()).unwrap();
        assert_eq!(result["outcome"], expected);
        assert_eq!(result["canonical"], canonical.to_str().unwrap());
        assert_eq!(result["alias"], alias.to_str().unwrap());
        result
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = temp_root();
        let canonical = root.path().join("dispatcher/projects");
        let alias = root.path().join("alias");
        (root, canonical, alias)
    }

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }

    #[test]
    fn new_namespace_is_create_only_silent_and_idempotent() {
        let (_root, canonical, alias) = fixture();
        assert_eq!(
            execute("check", &canonical, &alias, false),
            (1, String::new(), String::new())
        );
        for _ in 0..2 {
            assert_eq!(
                execute("create", &canonical, &alias, false),
                (0, String::new(), String::new())
            );
            assert_eq!(fs::read_link(&alias).unwrap(), canonical);
            assert_eq!(fs::read_dir(&canonical).unwrap().count(), 0);
            report(&canonical, &alias, "compatible");
        }
    }

    #[test]
    fn identical_staging_roots_need_no_alias() {
        let (_root, canonical, _) = fixture();
        assert_eq!(execute("create", &canonical, &canonical, false).0, 0);
        assert!(!fs::symlink_metadata(&canonical).unwrap().is_symlink());
        report(&canonical, &canonical, "compatible");
    }

    #[test]
    fn dangling_correct_and_relative_aliases_are_preserved() {
        for relative in [false, true] {
            let (root, canonical, alias) = fixture();
            let target = if relative {
                PathBuf::from("dispatcher/projects")
            } else {
                canonical.clone()
            };
            symlink(&target, &alias).unwrap();
            let identity = fs::symlink_metadata(&alias).unwrap().ino();
            report(&canonical, &alias, "canonical_missing");
            assert!(!root.path().join("dispatcher").exists());
            assert_eq!(execute("create", &canonical, &alias, false).0, 0);
            assert_eq!(fs::symlink_metadata(&alias).unwrap().ino(), identity);
            assert_eq!(fs::read_link(&alias).unwrap(), target);
        }
    }

    #[test]
    fn a_missing_canonical_name_reuses_only_a_real_symlink_target() {
        let (root, canonical, alias) = fixture();
        let physical = root.path().join("physical");
        fs::create_dir(&physical).unwrap();
        fs::write(physical.join("keep"), b"source contents").unwrap();
        symlink(&physical, &alias).unwrap();
        let alias_inode = fs::symlink_metadata(&alias).unwrap().ino();
        let observed = report(&canonical, &alias, "canonical_missing");
        assert_eq!(observed["alias_physical"], physical.to_str().unwrap());
        assert!(!canonical.parent().unwrap().exists());
        for _ in 0..2 {
            assert_eq!(execute("create", &canonical, &alias, false).0, 0);
            assert_eq!(fs::read_link(&canonical).unwrap(), physical);
            assert_eq!(fs::symlink_metadata(&alias).unwrap().ino(), alias_inode);
        }
        assert_eq!(
            fs::read(canonical.join("keep")).unwrap(),
            b"source contents"
        );
    }

    #[test]
    fn conflicting_directory_or_dangling_alias_never_creates_a_second_tree() {
        for dangling in [false, true] {
            let (root, canonical, alias) = fixture();
            let physical = root.path().join("elsewhere");
            if dangling {
                symlink(&physical, &alias).unwrap();
            } else {
                fs::create_dir(&alias).unwrap();
                fs::write(alias.join("keep"), b"unfinished evidence").unwrap();
            }
            let before = fs::symlink_metadata(&alias).unwrap().ino();
            let (status, stdout, stderr) = execute("create", &canonical, &alias, false);
            assert_eq!(status, REFUSAL_EXIT);
            assert!(stdout.is_empty());
            assert!(stderr.contains("RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: conflicting_alias_base\n"));
            assert!(!canonical.exists());
            assert!(!physical.exists());
            assert_eq!(fs::symlink_metadata(&alias).unwrap().ino(), before);
            if !dangling {
                assert_eq!(
                    fs::read(alias.join("keep")).unwrap(),
                    b"unfinished evidence"
                );
                assert_eq!(fs::read_dir(&alias).unwrap().count(), 1);
            }
        }
    }

    #[test]
    fn conflicting_worker_roots_report_only_escaped_metadata() {
        let (root, canonical, alias) = fixture();
        let physical = root.path().join("physical\t\u{1b}[31m-é-😀");
        fs::create_dir_all(&canonical).unwrap();
        fs::create_dir(&physical).unwrap();
        fs::write(physical.join("keep"), b"private source sentinel").unwrap();
        symlink(&physical, &alias).unwrap();
        let inode = fs::symlink_metadata(&alias).unwrap().ino();
        let checked = report(&canonical, &alias, "conflicting_alias_base");
        assert_eq!(checked["alias_physical"], physical.to_str().unwrap());
        let (status, stdout, stderr) = execute("create", &canonical, &alias, false);
        assert_eq!(status, REFUSAL_EXIT);
        assert!(stdout.is_empty());
        assert!(!stderr.contains(['\t', '\u{1b}']));
        assert!(stderr.is_ascii());
        assert!(!stderr.contains("private source sentinel"));
        assert_eq!(fs::symlink_metadata(&alias).unwrap().ino(), inode);
        assert_eq!(
            fs::read(physical.join("keep")).unwrap(),
            b"private source sentinel"
        );
    }

    #[test]
    fn files_and_missing_aliases_are_reported_without_mutation() {
        for canonical_file in [true, false] {
            let (_root, canonical, alias) = fixture();
            if canonical_file {
                fs::create_dir_all(canonical.parent().unwrap()).unwrap();
                fs::write(&canonical, b"canonical file").unwrap();
                report(&canonical, &alias, "canonical_not_directory");
                let (status, _, stderr) = execute("create", &canonical, &alias, false);
                assert_eq!(status, REFUSAL_EXIT);
                assert!(
                    stderr.contains("RCH_SOURCE_TOPOLOGY_INCOMPATIBLE: canonical_not_directory")
                );
                assert_eq!(fs::read(&canonical).unwrap(), b"canonical file");
                assert!(!alias.exists());
            } else {
                fs::create_dir_all(&canonical).unwrap();
                report(&canonical, &alias, "alias_missing");
                assert!(!alias.exists());
                fs::write(&alias, b"alias file").unwrap();
                report(&canonical, &alias, "alias_not_directory");
                assert_eq!(execute("create", &canonical, &alias, false).0, REFUSAL_EXIT);
                assert_eq!(fs::read(&alias).unwrap(), b"alias file");
            }
        }
    }

    #[test]
    fn two_matching_symlinks_remain_unchanged() {
        let (root, canonical, alias) = fixture();
        let physical = root.path().join("physical");
        fs::create_dir(&physical).unwrap();
        fs::create_dir_all(canonical.parent().unwrap()).unwrap();
        symlink(&physical, &canonical).unwrap();
        symlink(&physical, &alias).unwrap();
        let identities = (
            fs::symlink_metadata(&canonical).unwrap().ino(),
            fs::symlink_metadata(&alias).unwrap().ino(),
        );
        assert_eq!(execute("create", &canonical, &alias, false).0, 0);
        report(&canonical, &alias, "compatible");
        assert_eq!(
            identities,
            (
                fs::symlink_metadata(&canonical).unwrap().ino(),
                fs::symlink_metadata(&alias).unwrap().ino()
            )
        );
    }

    #[test]
    fn native_resolution_handles_parent_components_after_symlinks_and_missing_paths() {
        let (root, _, _) = fixture();
        let physical = root.path().join("physical/child");
        fs::create_dir_all(&physical).unwrap();
        let link = root.path().join("link");
        symlink("physical/child", &link).unwrap();
        assert_eq!(
            resolve_missing(&link.join("../missing")).unwrap(),
            root.path().join("physical/missing")
        );
        assert_eq!(
            resolve_missing(&root.path().join("absent/../link")).unwrap(),
            physical
        );
    }

    #[test]
    fn loops_and_ambiguous_targets_refuse_without_creating_aliases() {
        for target in ["canonical", "physical\n", "physical\r"] {
            let root = temp_root();
            let canonical = root.path().join("canonical");
            let alias = root.path().join("alias");
            if target != "canonical" {
                fs::create_dir(root.path().join(target)).unwrap();
            }
            symlink(target, &canonical).unwrap();
            let checked = report(&canonical, &canonical, "unavailable");
            assert!(checked["canonical_physical"].is_null());
            assert_eq!(execute("create", &canonical, &alias, false).0, REFUSAL_EXIT);
            assert!(fs::symlink_metadata(&alias).is_err());
        }
    }

    #[test]
    fn report_cannot_select_mutation_and_invalid_arguments_are_bounded() {
        let (root, canonical, alias) = fixture();
        assert_eq!(execute("create", &canonical, &alias, true).0, REFUSAL_EXIT);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        for arguments in [
            vec![],
            vec!["probe".into(), "extra".into()],
            vec!["check".into(), "/".into(), "/alias".into()],
            vec![
                "create".into(),
                format!("/{}", "x".repeat(MAX_PATH_BYTES)),
                "/alias".into(),
            ],
        ] {
            assert_eq!(
                run(&arguments, &mut Vec::new(), &mut Vec::new()),
                REFUSAL_EXIT
            );
        }
    }

    #[test]
    fn concurrent_initializers_do_not_replace_or_nest_names() {
        let (root, canonical, alias) = fixture();
        let gate = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let canonical = &canonical;
                let alias = &alias;
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    assert_eq!(execute("create", canonical, alias, false).0, 0);
                });
            }
        });
        assert_eq!(fs::read_link(&alias).unwrap(), canonical);
        assert_eq!(fs::read_dir(&canonical).unwrap().count(), 0);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }
}
