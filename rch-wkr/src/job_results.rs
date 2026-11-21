//! Prepare fresh job outputs without destroying any previous result bytes.
//!
//! The caller holds the source activity grant from synchronization through job
//! execution. This helper retains all traversed directory descriptors, seals a
//! durable intent in a new sibling directory, moves each old output there with
//! no-replace semantics, and creates empty output directories. An interrupted
//! preparation never grants execution and is never automatically repeated.

use anyhow::{Context, Result, ensure};
use rch_common::job_results::{JobResultsPreparationRequest, MAX_REQUEST_BYTES};
use std::io::{Read, Write};

const REFUSED_EXIT: i32 = 74;

/// Run before the async runtime or optional log files are initialized.
pub fn main() -> i32 {
    let result = read_request(std::io::stdin().lock()).and_then(prepare);
    match result {
        Ok(response) => match std::io::stdout().lock().write_all(&response) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("RCH_JOB_RESULTS_UNCONFIRMED: {error}");
                REFUSED_EXIT
            }
        },
        Err(error) => {
            eprintln!("RCH_JOB_RESULTS_REFUSED: {error:#}");
            REFUSED_EXIT
        }
    }
}

fn read_request(reader: impl Read) -> Result<JobResultsPreparationRequest> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read fresh-results request")?;
    ensure!(
        bytes.len() <= MAX_REQUEST_BYTES,
        "fresh-results request too large"
    );
    let request: JobResultsPreparationRequest =
        serde_json::from_slice(&bytes).context("decode fresh-results request")?;
    request.validate().map_err(anyhow::Error::msg)?;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn prepare(request: JobResultsPreparationRequest) -> Result<Vec<u8>> {
    linux::prepare_with(request, |_, _| Ok(()))
}

#[cfg(not(target_os = "linux"))]
fn prepare(_request: JobResultsPreparationRequest) -> Result<Vec<u8>> {
    anyhow::bail!("fresh job results require Linux no-replace directory retention")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rch_common::job_results::{
        JobResultsPreparationResponse, JobResultsPreparationResult, PreviousResultDirectory,
        SCHEMA_VERSION,
    };
    use rustix::fd::OwnedFd;
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, RenameFlags, Stat};
    use rustix::io::Errno;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::sync::Arc;

    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const MAX_COMPONENTS: usize = 4096;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Observation {
        Validated,
        IntentDurable,
        BeforeRetention,
        Retained,
        FreshCreated,
        BeforeOutcome,
    }

    fn same_inode(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev && left.st_ino == right.st_ino
    }

    fn metadata(parent: &OwnedFd, name: &str) -> Result<Option<Stat>> {
        match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(info) => Ok(Some(info)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error).context("inspect job result directory"),
        }
    }

    /// Each directory retains its entire anchored ancestry until acknowledgement.
    /// Descriptor-relative operations cannot be redirected through a symlink;
    /// verification also refuses detached or replaced parents before success.
    struct Directory {
        descriptor: OwnedFd,
        parent: Option<Arc<Self>>,
        name: String,
    }

    impl Directory {
        fn absolute(path: &str) -> Result<Arc<Self>> {
            let mut directory = Arc::new(Self {
                descriptor: rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())?,
                parent: None,
                name: String::new(),
            });
            for component in path[1..].split('/') {
                directory = directory.child(component)?;
            }
            directory.verify()?;
            Ok(directory)
        }

        fn child(self: &Arc<Self>, name: &str) -> Result<Arc<Self>> {
            self.verify()?;
            let descriptor =
                rustix::fs::openat(&self.descriptor, name, DIRECTORY_FLAGS, Mode::empty())
                    .with_context(|| {
                        format!("open result path component {name:?} without following links")
                    })?;
            let child = Arc::new(Self {
                descriptor,
                parent: Some(self.clone()),
                name: name.to_owned(),
            });
            child.verify()?;
            Ok(child)
        }

        fn create(self: &Arc<Self>, name: &str, mode: Mode) -> Result<Arc<Self>> {
            self.verify()?;
            // EEXIST is always a refusal, including for a directory. An
            // unrecognized prior preparation or concurrent writer owns it.
            rustix::fs::mkdirat(&self.descriptor, name, mode)
                .with_context(|| format!("exclusively create result directory {name:?}"))?;
            let child = self.child(name)?;
            child.require_owned()?;
            rustix::fs::fsync(&child.descriptor)?;
            rustix::fs::fsync(&self.descriptor)?;
            child.verify()?;
            Ok(child)
        }

        fn require_owned(&self) -> Result<()> {
            ensure!(
                rustix::fs::fstat(&self.descriptor)?.st_uid == rustix::process::geteuid().as_raw(),
                "result directory has a foreign owner"
            );
            Ok(())
        }

        fn verify(&self) -> Result<()> {
            let mut child = self;
            while let Some(parent) = child.parent.as_ref() {
                let named = rustix::fs::statat(
                    &parent.descriptor,
                    child.name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
                ensure!(
                    FileType::from_raw_mode(named.st_mode) == FileType::Directory
                        && same_inode(&named, &rustix::fs::fstat(&child.descriptor)?),
                    "result directory ancestry changed during preparation"
                );
                child = parent;
            }
            Ok(())
        }

        fn require_empty(&self) -> Result<()> {
            self.verify()?;
            for entry in Dir::read_from(&self.descriptor)? {
                let entry = entry?;
                ensure!(
                    matches!(entry.file_name().to_bytes(), b"." | b".."),
                    "fresh result directory acquired content before execution"
                );
            }
            self.verify()
        }
    }

    type SourceDirectories = BTreeMap<String, Option<Arc<Directory>>>;

    fn parent_and_name(relative: &str) -> (&str, &str) {
        relative.rsplit_once('/').unwrap_or(("", relative))
    }

    fn prevalidate(root: Arc<Directory>, result_dirs: &[String]) -> Result<SourceDirectories> {
        let mut directories = BTreeMap::from([(String::new(), Some(root))]);
        for result in result_dirs {
            let mut relative = String::new();
            for component in result.split('/') {
                let parent = relative.clone();
                if !relative.is_empty() {
                    relative.push('/');
                }
                relative.push_str(component);
                if directories.contains_key(&relative) {
                    continue;
                }
                ensure!(
                    directories.len() < MAX_COMPONENTS,
                    "too many result path components"
                );
                let directory = match directories.get(&parent).and_then(Option::as_ref) {
                    Some(parent) => match metadata(&parent.descriptor, component)? {
                        Some(info) => {
                            ensure!(
                                FileType::from_raw_mode(info.st_mode) == FileType::Directory,
                                "result path {relative:?} is not a plain directory"
                            );
                            let directory = parent.child(component)?;
                            directory.require_owned()?;
                            ensure!(
                                same_inode(&info, &rustix::fs::fstat(&directory.descriptor)?),
                                "result path changed during prevalidation"
                            );
                            Some(directory)
                        }
                        None => None,
                    },
                    None => None,
                };
                directories.insert(relative.clone(), directory);
            }
        }
        verify_source_observations(&directories)?;
        Ok(directories)
    }

    fn verify_source_observations(directories: &SourceDirectories) -> Result<()> {
        for (relative, directory) in directories {
            match directory {
                Some(directory) => directory.verify()?,
                None => {
                    let (parent, name) = parent_and_name(relative);
                    if let Some(parent) = directories.get(parent).and_then(Option::as_ref) {
                        parent.verify()?;
                        ensure!(
                            metadata(&parent.descriptor, name)?.is_none(),
                            "previously absent result path {relative:?} appeared"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn create_source_directory(
        relative: &str,
        directories: &mut SourceDirectories,
    ) -> Result<Arc<Directory>> {
        if let Some(directory) = directories.get(relative).and_then(Option::as_ref) {
            directory.verify()?;
            return Ok(directory.clone());
        }
        ensure!(
            directories.contains_key(relative),
            "unplanned result directory"
        );
        let (parent, name) = parent_and_name(relative);
        let parent = create_source_directory(parent, directories)?;
        let created = parent.create(name, Mode::from_raw_mode(0o755))?;
        directories.insert(relative.to_owned(), Some(created.clone()));
        Ok(created)
    }

    fn create_retention_parent(
        relative: &str,
        directories: &mut BTreeMap<String, Arc<Directory>>,
    ) -> Result<Arc<Directory>> {
        if let Some(directory) = directories.get(relative) {
            directory.verify()?;
            return Ok(directory.clone());
        }
        let (parent, name) = parent_and_name(relative);
        let parent = create_retention_parent(parent, directories)?;
        let created = parent.create(name, Mode::from_raw_mode(0o700))?;
        directories.insert(relative.to_owned(), created.clone());
        Ok(created)
    }

    fn seal(directory: &Directory, name: &str, contents: &[u8]) -> Result<()> {
        directory.verify()?;
        let descriptor = rustix::fs::openat(
            &directory.descriptor,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let identity = rustix::fs::fstat(&descriptor)?;
        let mut file = File::from(descriptor);
        file.write_all(contents)?;
        file.sync_all()?;
        rustix::fs::fsync(&directory.descriptor)?;
        directory.verify()?;
        ensure!(
            same_inode(
                &identity,
                &rustix::fs::statat(&directory.descriptor, name, AtFlags::SYMLINK_NOFOLLOW)?
            ),
            "result preparation journal changed while sealing"
        );
        Ok(())
    }

    pub(super) fn prepare_with(
        request: JobResultsPreparationRequest,
        mut observe: impl FnMut(Observation, &str) -> Result<()>,
    ) -> Result<Vec<u8>> {
        request.validate().map_err(anyhow::Error::msg)?;
        ensure!(
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                "",
                rustix::fs::CWD,
                "",
                RenameFlags::NOREPLACE,
            ) == Err(Errno::NOENT),
            "Linux no-replace rename syscall unavailable"
        );
        let root = Directory::absolute(&request.source_root)?;
        root.require_owned()?;
        let mut source = prevalidate(root.clone(), &request.result_dirs)?;
        let parent = root.parent.as_ref().context("source root has no parent")?;
        let retention_name = request
            .retention_root
            .rsplit('/')
            .next()
            .context("missing retention basename")?;
        observe(Observation::Validated, "")?;
        verify_source_observations(&source)?;
        let retention = parent.create(retention_name, Mode::from_raw_mode(0o700))?;
        // Once this directory exists, every retry refuses, even if the process
        // dies before request.json is sealed. No ambiguous attempt is reused.
        seal(&retention, "request.json", &serde_json::to_vec(&request)?)?;
        observe(Observation::IntentDurable, "")?;
        let old = retention.create("old", Mode::from_raw_mode(0o700))?;
        let mut retained_parents = BTreeMap::from([(String::new(), old)]);
        let mut results = Vec::with_capacity(request.result_dirs.len());

        for relative in &request.result_dirs {
            verify_source_observations(&source)?;
            retention.verify()?;
            let existing = source.get(relative).and_then(Option::as_ref).cloned();
            let (parent_path, name) = parent_and_name(relative);
            let source_parent = create_source_directory(parent_path, &mut source)?;
            let (previous, retained_path) = if let Some(existing) = existing {
                let retained_parent = create_retention_parent(parent_path, &mut retained_parents)?;
                observe(Observation::BeforeRetention, relative)?;
                existing.verify()?;
                retained_parent.verify()?;
                let original = rustix::fs::fstat(&existing.descriptor)?;
                rustix::fs::renameat_with(
                    &source_parent.descriptor,
                    name,
                    &retained_parent.descriptor,
                    name,
                    RenameFlags::NOREPLACE,
                )
                .with_context(|| format!("retain previous result directory {relative:?}"))?;
                rustix::fs::fsync(&retained_parent.descriptor)?;
                rustix::fs::fsync(&source_parent.descriptor)?;
                source_parent.verify()?;
                retained_parent.verify()?;
                ensure!(
                    same_inode(
                        &original,
                        &rustix::fs::statat(
                            &retained_parent.descriptor,
                            name,
                            AtFlags::SYMLINK_NOFOLLOW,
                        )?
                    ),
                    "retained result directory does not match prevalidated source"
                );
                source.insert(relative.clone(), None);
                observe(Observation::Retained, relative)?;
                (
                    PreviousResultDirectory::Retained,
                    Some(format!("{}/old/{relative}", request.retention_root)),
                )
            } else {
                (PreviousResultDirectory::Absent, None)
            };
            let fresh = create_source_directory(relative, &mut source)?;
            fresh.require_empty()?;
            observe(Observation::FreshCreated, relative)?;
            results.push(JobResultsPreparationResult {
                result_dir: relative.clone(),
                previous,
                retained_path,
            });
        }

        observe(Observation::BeforeOutcome, "")?;
        verify_source_observations(&source)?;
        for relative in &request.result_dirs {
            source
                .get(relative)
                .and_then(Option::as_ref)
                .context("fresh result directory disappeared")?
                .require_empty()?;
        }
        let response = JobResultsPreparationResponse {
            schema_version: SCHEMA_VERSION,
            request,
            results,
        };
        response
            .validate_for(&response.request)
            .map_err(anyhow::Error::msg)?;
        let mut bytes = serde_json::to_vec(&response)?;
        bytes.push(b'\n');
        seal(&retention, "outcome.json", &bytes)?;
        verify_source_observations(&source)?;
        Ok(bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rch_common::job_results::retention_root_for;
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;

        struct Fixture {
            _directory: tempfile::TempDir,
            root: PathBuf,
            request: JobResultsPreparationRequest,
        }

        impl Fixture {
            fn new(results: &[&str]) -> Self {
                let directory = tempfile::tempdir().unwrap();
                let root = directory.path().join("source");
                fs::create_dir(&root).unwrap();
                let source_root = root.to_str().unwrap().to_owned();
                let plan_id = "0123456789abcdef0123456789abcdef".to_owned();
                let retention_root = retention_root_for(&source_root, &plan_id).unwrap();
                Self {
                    _directory: directory,
                    root,
                    request: JobResultsPreparationRequest {
                        schema_version: SCHEMA_VERSION,
                        plan_id,
                        source_root,
                        retention_root,
                        result_dirs: results.iter().map(|path| (*path).to_owned()).collect(),
                    },
                }
            }

            fn retained(&self, relative: &str) -> PathBuf {
                PathBuf::from(&self.request.retention_root).join(relative)
            }

            fn run(&self) -> Result<Vec<u8>> {
                prepare_with(self.request.clone(), |_, _| Ok(()))
            }
        }

        #[test]
        fn fresh_results_retains_old_bytes_and_starts_every_declared_directory_empty() {
            let fixture = Fixture::new(&["out", "reports/qa", "reports/new"]);
            fs::create_dir_all(fixture.root.join("out/nested")).unwrap();
            fs::write(
                fixture.root.join("out/nested/stale.bin"),
                b"old result bytes",
            )
            .unwrap();
            fs::create_dir_all(fixture.root.join("reports/qa")).unwrap();
            fs::write(fixture.root.join("reports/qa/old.json"), b"old receipt").unwrap();
            fs::write(fixture.root.join("source.rs"), b"untouched source").unwrap();

            let bytes = fixture.run().unwrap();
            let response: JobResultsPreparationResponse = serde_json::from_slice(&bytes).unwrap();
            response.validate_for(&fixture.request).unwrap();
            assert_eq!(
                response.results[0].previous,
                PreviousResultDirectory::Retained
            );
            assert_eq!(
                response.results[1].previous,
                PreviousResultDirectory::Retained
            );
            assert_eq!(
                response.results[2].previous,
                PreviousResultDirectory::Absent
            );
            for relative in &fixture.request.result_dirs {
                assert_eq!(
                    fs::read_dir(fixture.root.join(relative)).unwrap().count(),
                    0
                );
            }
            assert_eq!(
                fs::read(fixture.retained("old/out/nested/stale.bin")).unwrap(),
                b"old result bytes"
            );
            assert_eq!(
                fs::read(fixture.retained("old/reports/qa/old.json")).unwrap(),
                b"old receipt"
            );
            assert_eq!(
                fs::read(fixture.root.join("source.rs")).unwrap(),
                b"untouched source"
            );
            assert_eq!(fs::read(fixture.retained("outcome.json")).unwrap(), bytes);
            let intent: JobResultsPreparationRequest =
                serde_json::from_slice(&fs::read(fixture.retained("request.json")).unwrap())
                    .unwrap();
            assert_eq!(intent, fixture.request);
        }

        #[test]
        fn fresh_results_completed_or_incomplete_preparation_is_never_replayed() {
            for interrupted in [false, true] {
                let fixture = Fixture::new(&["out"]);
                fs::create_dir(fixture.root.join("out")).unwrap();
                fs::write(fixture.root.join("out/stale"), b"preserve me").unwrap();
                let first = prepare_with(fixture.request.clone(), |point, _| {
                    if interrupted && point == Observation::Retained {
                        anyhow::bail!("simulated interruption after durable retention");
                    }
                    Ok(())
                });
                assert_eq!(first.is_ok(), !interrupted);
                assert!(fixture.retained("request.json").is_file());
                assert_eq!(fixture.retained("outcome.json").exists(), !interrupted);
                assert!(fixture.run().is_err());
                assert_eq!(
                    fs::read(fixture.retained("old/out/stale")).unwrap(),
                    b"preserve me"
                );
                if !interrupted {
                    fs::write(fixture.root.join("out/new"), b"new job bytes").unwrap();
                    assert!(fixture.run().is_err());
                    assert_eq!(
                        fs::read(fixture.root.join("out/new")).unwrap(),
                        b"new job bytes"
                    );
                }
            }
        }

        #[test]
        fn fresh_results_checks_all_destinations_before_changing_any() {
            for symlinked in [false, true] {
                let fixture = Fixture::new(&["out", "later/child"]);
                fs::create_dir(fixture.root.join("out")).unwrap();
                fs::write(fixture.root.join("out/stale"), b"original").unwrap();
                if symlinked {
                    symlink(fixture.root.join("out"), fixture.root.join("later")).unwrap();
                } else {
                    fs::write(fixture.root.join("later"), b"not a directory").unwrap();
                }
                assert!(fixture.run().is_err());
                assert!(!fixture.retained("").exists());
                assert_eq!(
                    fs::read(fixture.root.join("out/stale")).unwrap(),
                    b"original"
                );
            }
        }

        #[test]
        fn fresh_results_moves_internal_links_without_traversing_their_targets() {
            let fixture = Fixture::new(&["out"]);
            let unrelated = fixture.root.with_file_name("unrelated");
            fs::create_dir(&unrelated).unwrap();
            fs::write(unrelated.join("keep"), b"outside the result tree").unwrap();
            fs::create_dir(fixture.root.join("out")).unwrap();
            symlink(&unrelated, fixture.root.join("out/link")).unwrap();

            fixture.run().unwrap();
            assert_eq!(
                fs::read_link(fixture.retained("old/out/link")).unwrap(),
                unrelated
            );
            assert_eq!(
                fs::read(unrelated.join("keep")).unwrap(),
                b"outside the result tree"
            );
            assert_eq!(fs::read_dir(fixture.root.join("out")).unwrap().count(), 0);
        }

        #[test]
        fn fresh_results_refuses_a_previously_absent_directory_that_appears_before_intent() {
            let fixture = Fixture::new(&["out"]);
            let result = prepare_with(fixture.request.clone(), |point, _| {
                if point == Observation::Validated {
                    fs::create_dir(fixture.root.join("out"))?;
                    fs::write(fixture.root.join("out/other"), b"another preparation")?;
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(!fixture.retained("").exists());
            assert_eq!(
                fs::read(fixture.root.join("out/other")).unwrap(),
                b"another preparation"
            );
        }

        #[test]
        fn fresh_results_refuses_source_root_alias_and_existing_retention_destination() {
            let fixture = Fixture::new(&["out"]);
            let alias = fixture.root.with_file_name("alias");
            symlink(&fixture.root, &alias).unwrap();
            let mut request = fixture.request.clone();
            request.source_root = alias.to_str().unwrap().to_owned();
            request.retention_root =
                retention_root_for(&request.source_root, &request.plan_id).unwrap();
            assert!(prepare_with(request, |_, _| Ok(())).is_err());
            assert!(!fixture.root.join("out").exists());

            fs::create_dir(fixture.retained("")).unwrap();
            fs::write(fixture.retained("sentinel"), b"unrelated attempt").unwrap();
            assert!(fixture.run().is_err());
            assert_eq!(
                fs::read(fixture.retained("sentinel")).unwrap(),
                b"unrelated attempt"
            );
            assert!(!fixture.root.join("out").exists());
        }

        #[test]
        fn fresh_results_never_overwrites_a_late_retention_collision() {
            let fixture = Fixture::new(&["out"]);
            fs::create_dir(fixture.root.join("out")).unwrap();
            fs::write(fixture.root.join("out/stale"), b"source").unwrap();
            let result = prepare_with(fixture.request.clone(), |point, _| {
                if point == Observation::BeforeRetention {
                    fs::create_dir(fixture.retained("old/out"))?;
                    fs::write(fixture.retained("old/out/other"), b"retained collision")?;
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(fs::read(fixture.root.join("out/stale")).unwrap(), b"source");
            assert_eq!(
                fs::read(fixture.retained("old/out/other")).unwrap(),
                b"retained collision"
            );
            assert!(!fixture.retained("outcome.json").exists());
        }

        #[test]
        fn fresh_results_refuses_late_source_aliases_and_unexpected_fresh_content() {
            for replace_parent in [false, true] {
                let fixture = Fixture::new(&["out"]);
                let result = prepare_with(fixture.request.clone(), |point, _| {
                    if point == Observation::BeforeOutcome {
                        if replace_parent {
                            let detached = fixture.root.with_file_name("detached");
                            fs::rename(&fixture.root, &detached)?;
                            symlink(&detached, &fixture.root)?;
                        } else {
                            fs::write(fixture.root.join("out/unexpected"), b"another writer")?;
                        }
                    }
                    Ok(())
                });
                assert!(result.is_err());
                assert!(!fixture.retained("outcome.json").exists());
            }
        }

        #[test]
        fn fresh_results_interrupted_intent_never_reports_completion() {
            let fixture = Fixture::new(&["out"]);
            let result = prepare_with(fixture.request.clone(), |point, _| {
                if point == Observation::IntentDurable {
                    anyhow::bail!("interrupted before any result mutation");
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(fixture.retained("request.json").is_file());
            assert!(!fixture.root.join("out").exists());
            assert!(!fixture.retained("outcome.json").exists());
            assert!(fixture.run().is_err());
        }

        #[test]
        fn fresh_results_request_input_is_bounded_and_requires_complete_json() {
            let fixture = Fixture::new(&["out"]);
            let bytes = serde_json::to_vec(&fixture.request).unwrap();
            assert_eq!(read_request(bytes.as_slice()).unwrap(), fixture.request);
            assert!(read_request(&bytes[..bytes.len() - 1]).is_err());
            assert!(read_request(vec![b' '; MAX_REQUEST_BYTES + 1].as_slice()).is_err());
        }
    }
}
