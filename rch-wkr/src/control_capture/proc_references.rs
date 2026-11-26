//! Produce pathname evidence for the checked GC snapshot writer on Linux.

use rch_common::process_identity::{ProcessObservation, observe_process};
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) fn capture() -> io::Result<i32> {
    if !matches!(
        observe_process(std::process::id()),
        ProcessObservation::Present(_)
    ) {
        return Err(io::Error::other(
            "procfs does not identify the observer's PID namespace",
        ));
    }
    check_proc_mount(&fs::read_to_string("/proc/self/mountinfo")?)?;
    let mut paths = References {
        output: io::BufWriter::new(io::stdout().lock()),
        seen: HashSet::new(),
    };
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(pid) = decimal_id(&entry.file_name()) {
            scan_process(&entry.path(), pid, &mut paths, |pid| {
                observe_process(pid) == ProcessObservation::Absent
            })?;
        }
    }
    paths.output.flush()?;
    Ok(0)
}

// A procfs which silently removes foreign PIDs cannot certify a complete
// inventory even if every visible read succeeded. A bind over a numeric
// process directory or any of its children can similarly mask references.
fn check_proc_mount(info: &str) -> io::Result<()> {
    let mut found = false;
    for line in info.lines() {
        let (mount, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| io::Error::other("invalid proc mount inventory"))?;
        let fields: Vec<_> = mount.split_ascii_whitespace().collect();
        let Some(point) = fields.get(4).copied() else {
            return Err(io::Error::other("missing mount point"));
        };
        if point == "/proc" {
            let mut fs = filesystem.split_ascii_whitespace();
            if found || fields.get(3) != Some(&"/") || fs.next() != Some("proc") {
                return Err(io::Error::other("ambiguous procfs mount"));
            }
            let options = fs
                .nth(1)
                .ok_or_else(|| io::Error::other("missing procfs options"))?;
            if options.split(',').any(|opt| {
                opt.starts_with("hidepid=") && !matches!(opt, "hidepid=off" | "hidepid=0")
            }) {
                return Err(io::Error::other("procfs process visibility is restricted"));
            }
            found = true;
        } else if point
            .strip_prefix("/proc/")
            .and_then(|p| p.split('/').next())
            .is_some_and(|name| decimal_id(OsStr::new(name)).is_some())
        {
            return Err(io::Error::other("a process directory has a nested mount"));
        }
    }
    if !found {
        return Err(io::Error::other("procfs mount missing"));
    }
    Ok(())
}

fn decimal_id(value: &OsStr) -> Option<u32> {
    let value = value.to_str()?;
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(nix::libc::ESRCH)
}

// A directory entry returned by readdir can vanish before readlink. Check
// both observations and never convert EACCES or another error into absence.
fn vanished_entry(path: &Path, error: &io::Error) -> bool {
    disappeared(error) && fs::symlink_metadata(path).is_err_and(|e| disappeared(&e))
}

struct References<W> {
    output: W,
    // Bound memory on large workers. Additional paths are still emitted.
    seen: HashSet<OsString>,
}

impl<W: Write> References<W> {
    fn link(&mut self, link: &Path) -> io::Result<()> {
        let target = fs::read_link(link)?;
        if !target.is_absolute() {
            return Ok(()); // sockets, pipes and anonymous inodes
        }
        let target = target.as_os_str();
        if target.as_bytes().contains(&b'\n') {
            return Err(io::Error::other(
                "proc reference cannot be framed as one pathname",
            ));
        }
        if !self.seen.contains(target) {
            self.output.write_all(target.as_bytes())?;
            self.output.write_all(b"\n")?;
            if self.seen.len() < 4096 {
                self.seen.insert(target.to_owned());
            }
        }
        Ok(())
    }

    fn descriptor(&mut self, path: &Path) -> io::Result<()> {
        match self.link(path) {
            Err(error) if vanished_entry(path, &error) => Ok(()),
            result => result,
        }
    }
}

fn scan_task<W: Write>(task: &Path, paths: &mut References<W>) -> io::Result<()> {
    paths.link(&task.join("cwd"))?;
    paths.link(&task.join("root"))?;
    for fd in fs::read_dir(task.join("fd"))? {
        paths.descriptor(&fd?.path())?;
    }
    Ok(())
}

fn scan_process<W: Write>(
    process: &Path,
    pid: u32,
    paths: &mut References<W>,
    absent: impl FnOnce(u32) -> bool,
) -> io::Result<()> {
    let mut scan = || -> io::Result<()> {
        let mut saw_leader = false;
        for task in fs::read_dir(process.join("task"))? {
            let task = task?;
            let tid =
                decimal_id(&task.file_name()).ok_or_else(|| io::Error::other("invalid task ID"))?;
            saw_leader |= tid == pid;
            let path = task.path();
            if let Err(error) = scan_task(&path, paths) {
                if tid == pid || !vanished_entry(&path, &error) {
                    return Err(error);
                }
            }
        }
        if !saw_leader {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        Ok(())
    };
    match scan() {
        // The process identity witness also handles single-thread zombies.
        // A zombie leader with surviving threads is never group absence.
        Err(error) if disappeared(&error) && absent(pid) => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn references() -> References<Vec<u8>> {
        References {
            output: Vec::new(),
            seen: HashSet::new(),
        }
    }

    fn task(root: &Path, id: u32) -> std::path::PathBuf {
        let path = root.join("task").join(id.to_string());
        fs::create_dir_all(path.join("fd")).unwrap();
        symlink("/working directory", path.join("cwd")).unwrap();
        symlink("/", path.join("root")).unwrap();
        path
    }

    #[test]
    fn scan_records_sibling_descriptors_and_deduplicates_shared_roots() {
        let root = tempfile::tempdir().unwrap();
        task(root.path(), 10);
        let sibling = task(root.path(), 11);
        symlink("/build/.rch-target/out", sibling.join("fd/3")).unwrap();
        symlink("socket:[42]", sibling.join("fd/4")).unwrap();
        let mut paths = references();
        scan_process(root.path(), 10, &mut paths, |_| false).unwrap();
        let mut lines: Vec<_> = std::str::from_utf8(&paths.output)
            .unwrap()
            .lines()
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, ["/", "/build/.rch-target/out", "/working directory"]);
    }

    #[test]
    fn a_closed_descriptor_is_absent_but_a_permission_error_is_unknown() {
        let root = tempfile::tempdir().unwrap();
        let fd = task(root.path(), 10).join("fd/12");
        symlink("/job/held", &fd).unwrap();
        let listed = fs::read_dir(fd.parent().unwrap())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::remove_file(&fd).unwrap();
        let mut paths = references();
        paths.descriptor(&listed).unwrap();
        assert!(paths.output.is_empty());
        assert!(!vanished_entry(
            &listed,
            &io::ErrorKind::PermissionDenied.into()
        ));
    }

    #[test]
    fn missing_process_witness_requires_confirmed_group_absence() {
        let root = tempfile::tempdir().unwrap();
        let leader = task(root.path(), 10);
        task(root.path(), 11);
        fs::remove_file(leader.join("cwd")).unwrap();
        assert!(scan_process(root.path(), 10, &mut references(), |_| false).is_err());
        let vanished = root.path().join("vanished");
        scan_process(&vanished, 12, &mut references(), |pid| pid == 12).unwrap();
        assert!(scan_process(&vanished, 12, &mut references(), |_| false).is_err());
    }

    #[test]
    fn partial_or_unframeable_observations_are_never_free() {
        let root = tempfile::tempdir().unwrap();
        let path = task(root.path(), 10);
        let fd = path.join("fd/3");
        fs::write(&fd, "not a proc link").unwrap();
        assert!(scan_process(root.path(), 10, &mut references(), |_| true).is_err());
        fs::remove_file(&fd).unwrap();
        symlink("/work/new\nline", &fd).unwrap();
        assert!(scan_process(root.path(), 10, &mut references(), |_| true).is_err());
        fs::remove_file(&fd).unwrap();
        // Privileged callers bypass mode bits. Exercise the real denial
        // whenever this test runs as an unprivileged worker account.
        let descriptor_dir = path.join("fd");
        fs::set_permissions(&descriptor_dir, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&descriptor_dir).is_err() {
            assert!(scan_process(root.path(), 10, &mut references(), |_| true).is_err());
        }
        fs::set_permissions(descriptor_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn visibility_rejects_hidden_processes_and_mounts_covering_task_entries() {
        let normal = "15 1 0:5 / /proc rw - proc proc rw,hidepid=off\n";
        assert!(check_proc_mount(normal).is_ok());
        assert!(check_proc_mount(&normal.replace("hidepid=off", "hidepid=2")).is_err());
        assert!(check_proc_mount(&normal.replace(" / /proc ", " /123 /proc ")).is_err());
        assert!(
            check_proc_mount(&format!(
                "{normal}22 15 0:7 / /proc/123/fd rw - tmpfs tmpfs rw\n"
            ))
            .is_err()
        );
        assert!(check_proc_mount("").is_err());
    }
}
