//! Bind a foreground SSH master to the caller even when the caller is killed.
//!
//! The helper owns the master process group; its stdin is a private lifetime
//! pipe from the caller. No PID sweep or process-name match grants authority.
//! Parent cleanup closes that pipe, never kills the helper before it can reap
//! the master. Linux's dedicated helper also reaps adopted proxy descendants.

use super::{BoundedLines, OwnedProcessGroup};
use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const ARGUMENT: &str = "--rch-internal-ssh-master-guardian-v1";
const EXECUTABLE_NAME: &str = "rch-ssh-guard";
const RESULT: &str = "RCH_SSH_MASTER_RESULT_V1 ";
const RESULT_LIMIT: usize = 128 * 1024;
static REGISTERED: AtomicBool = AtomicBool::new(false);
#[cfg(not(target_os = "linux"))]
static HELPER_PATH: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();

/// Call before constructing a runtime or handling ordinary CLI/hook input.
///
/// Normal startup only registers helper support; resolving the executable is
/// deferred until an SSH master is needed. An internal invocation returns its
/// exit code, which the binary must use to exit without ordinary dispatch.
pub fn run_ssh_master_guardian_if_requested() -> Option<i32> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new(ARGUMENT)) {
        REGISTERED.store(true, Ordering::Release);
        return None;
    }
    Some(run_guardian(arguments.collect()))
}

/// The caller normally owns its TempDir. Once a guardian has spawned, only
/// that guardian may remove it: dropping the caller's runtime must not unlink
/// the socket while the master is still alive.
pub(super) struct SshControlDir {
    directory: Option<tempfile::TempDir>,
    guarded: AtomicBool,
}

impl SshControlDir {
    pub(super) fn new(directory: tempfile::TempDir) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        // TempDir defaults to ordinary directory permissions filtered by the
        // caller's umask, not 0700. Protect this fresh directory before any
        // executable, log, socket or lifetime handoff can be placed inside it.
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            directory: Some(directory),
            guarded: AtomicBool::new(false),
        })
    }

    pub(super) fn path(&self) -> &Path {
        self.directory
            .as_ref()
            .expect("live control directory")
            .path()
    }
}

impl Drop for SshControlDir {
    fn drop(&mut self) {
        if self.guarded.load(Ordering::Acquire)
            && let Some(directory) = self.directory.take()
        {
            let _ = directory.keep();
        }
    }
}

pub(super) enum SshChild {
    Direct(OwnedProcessGroup),
    Guarded(GuardedChild),
}

impl SshChild {
    pub(super) fn spawn(
        command: &mut tokio::process::Command,
        control_dir: Option<&Arc<SshControlDir>>,
    ) -> io::Result<Self> {
        if let Some(directory) = control_dir
            && (REGISTERED.load(Ordering::Acquire) || cfg!(test))
        {
            // A registered binary never silently falls back to an unguarded
            // master when helper setup, spawn, or execution fails.
            return GuardedChild::spawn(command, directory).map(Self::Guarded);
        }
        OwnedProcessGroup::spawn(command).map(Self::Direct)
    }

    pub(super) fn start_kill(&mut self) -> io::Result<()> {
        match self {
            Self::Direct(child) => child.start_kill(),
            Self::Guarded(child) => {
                child.owner.take();
                Ok(())
            }
        }
    }

    pub(super) async fn wait(&mut self) -> io::Result<ExitStatus> {
        match self {
            Self::Direct(child) => child.wait().await,
            Self::Guarded(child) => child.wait().await,
        }
    }

    pub(super) fn diagnostic(&self) -> &str {
        match self {
            Self::Direct(_) => "",
            Self::Guarded(child) => child
                .result
                .as_ref()
                .map_or("", |result| &result.diagnostic),
        }
    }
}

pub(super) struct GuardedChild {
    reaped: tokio::sync::watch::Receiver<Option<Result<ExitStatus, String>>>,
    // std/Tokio create this writer CLOEXEC; unrelated spawned commands cannot
    // keep the guardian's lifetime pipe open after the caller dies.
    owner: Option<std::process::ChildStdin>,
    output: BoundedLines<tokio::process::ChildStdout>,
    output_bytes: usize,
    result: Option<GuardianResult>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardianResult {
    status: i32,
    diagnostic: String,
}

impl GuardedChild {
    fn spawn(master: &tokio::process::Command, directory: &SshControlDir) -> io::Result<Self> {
        let identity = DirectoryIdentity::read(directory.path())?;
        let mut arguments = vec![
            OsString::from(std::process::id().to_string()),
            directory.path().as_os_str().to_owned(),
            OsString::from(identity.device.to_string()),
            OsString::from(identity.inode.to_string()),
            OsString::from(identity.uid.to_string()),
            master.as_std().get_program().to_owned(),
        ];
        arguments.extend(master.as_std().get_args().map(std::ffi::OsStr::to_owned));
        let mut helper = helper_command(arguments, directory.path())?;
        for (name, value) in master.as_std().get_envs() {
            match value {
                Some(value) => {
                    helper.env(name, value);
                }
                None => {
                    helper.env_remove(name);
                }
            }
        }
        if let Some(directory) = master.as_std().get_current_dir() {
            helper.current_dir(directory);
        }
        helper
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            // Killing this process would prevent it from stopping/reaping
            // its separately owned master group. EOF is the stop protocol.
            .kill_on_drop(false);
        directory.guarded.store(true, Ordering::Release);
        let mut child = match helper.as_std_mut().spawn() {
            Ok(child) => child,
            Err(error) => {
                directory.guarded.store(false, Ordering::Release);
                return Err(error);
            }
        };
        let owner = child.stdin.take().expect("piped guardian lifetime");
        let output = child.stdout.take().expect("piped guardian response");
        let (finished, reaped) = tokio::sync::watch::channel(None);
        // A runtime shutdown must not strand an exited guardian zombie while
        // the caller remains alive. This one blocking waiter owns the child
        // independently of Tokio, and never owns the lifetime writer.
        let owned = Arc::new(std::sync::Mutex::new(Some(child)));
        let waiter = owned.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("rch-ssh-guardian-reap".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let mut child = waiter
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take()
                    .expect("the waiter alone owns its guardian");
                let _ = finished.send(Some(child.wait().map_err(|error| error.to_string())));
            })
        {
            drop(owner);
            // The helper must not block on its bounded completion response
            // while this thread synchronously waits for it to exit.
            drop(output);
            // No waiter was started. Revoke the helper before synchronously
            // reaping the exact child; never abandon a successful spawn.
            if let Some(mut child) = owned
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
            {
                let _ = child.wait();
            }
            return Err(error);
        }
        Ok(Self {
            reaped,
            owner: Some(owner),
            output: BoundedLines::new(tokio::process::ChildStdout::from_std(output)?, RESULT_LIMIT),
            output_bytes: 0,
            result: None,
        })
    }

    async fn wait(&mut self) -> io::Result<ExitStatus> {
        while self.result.is_none() {
            let line = self.output.next_line().await?.ok_or_else(|| {
                io::Error::other("SSH guardian exited without confirming master teardown")
            })?;
            self.output_bytes = self.output_bytes.saturating_add(line.len());
            if self.output_bytes > RESULT_LIMIT {
                return Err(io::Error::other("SSH guardian response exceeds its limit"));
            }
            if let Some(result) = line.strip_prefix(RESULT) {
                self.result = Some(serde_json::from_str(result).map_err(io::Error::other)?);
            } else if !cfg!(test) {
                return Err(io::Error::other("invalid SSH guardian response"));
            }
            // A self-spawned libtest helper can prepend bounded harness text.
            // Production helpers accept only the one versioned response line.
        }
        let status = loop {
            if let Some(status) = self.reaped.borrow_and_update().clone() {
                break status.map_err(io::Error::other)?;
            }
            self.reaped
                .changed()
                .await
                .map_err(|_| io::Error::other("SSH guardian waiter ended without a result"))?;
        };
        if !status.success() {
            return Err(io::Error::other(format!("SSH guardian failed: {status}")));
        }
        Ok(ExitStatus::from_raw(
            self.result.as_ref().expect("response read above").status,
        ))
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        self.owner.take();
        // Child is intentionally not killed. Its independent guardian stops
        // and reaps the master even when the caller's runtime has gone away.
    }
}

fn helper_command(
    arguments: Vec<OsString>,
    directory: &Path,
) -> io::Result<tokio::process::Command> {
    let alias = directory.join(EXECUTABLE_NAME);
    #[cfg(target_os = "linux")]
    create_running_image_alias(&alias)?;
    #[cfg(not(target_os = "linux"))]
    {
        let executable = HELPER_PATH
            .get_or_init(|| {
                std::env::current_exe()
                    .and_then(std::fs::canonicalize)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|error| io::Error::other(error.clone()))?;
        create_executable_alias(executable, &alias)?;
    }
    // Use this basename even when the alias is a Linux symlink. Canonicalizing
    // it here would make a name-based `killall rchd` kill the guardian too.
    let mut helper = tokio::process::Command::new(alias);
    #[cfg(not(test))]
    helper.arg(ARGUMENT).args(arguments);
    #[cfg(test)]
    {
        use std::os::unix::ffi::OsStrExt;
        helper.args([
            "--exact",
            "ssh::master_guardian::tests::guardian_child",
            "--ignored",
            "--nocapture",
        ]);
        let arguments: Vec<_> = arguments.iter().map(|value| value.as_bytes()).collect();
        helper.env(
            "RCH_TEST_SSH_GUARDIAN_ARGUMENTS",
            serde_json::to_string(&arguments).map_err(io::Error::other)?,
        );
    }
    Ok(helper)
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(target_os = "linux")]
fn create_running_image_alias(alias: &Path) -> io::Result<()> {
    // This kernel-owned magic link opens the running image even after an
    // atomic upgrade unlinks its original pathname. Resolve it only inside
    // exec, while the fork child still owns that image; never cache readlink
    // text, canonicalize it, or tie it to the parent's continued existence.
    let executable = Path::new("/proc/self/exe");
    let original = std::fs::metadata(executable)?;
    if !original.is_file() {
        return Err(io::Error::other(
            "SSH guardian running image is not a regular file",
        ));
    }
    std::os::unix::fs::symlink(executable, alias)?;
    if !same_file(&original, &std::fs::metadata(alias)?) {
        return Err(io::Error::other(
            "SSH guardian running image identity changed",
        ));
    }
    Ok(())
}

#[cfg(any(not(target_os = "linux"), test))]
fn create_executable_alias(executable: &Path, alias: &Path) -> io::Result<()> {
    let original = std::fs::symlink_metadata(executable)?;
    if !original.is_file() {
        return Err(io::Error::other(
            "SSH guardian executable is not a regular file",
        ));
    }
    match std::fs::hard_link(executable, alias) {
        Ok(()) => {
            let linked = std::fs::symlink_metadata(alias)?;
            if !linked.is_file() || !same_file(&original, &linked) {
                return Err(io::Error::other("SSH guardian executable identity changed"));
            }
            // Do not chmod a hard link: it is the installed executable inode.
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::CrossesDevices
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::Unsupported
            ) =>
        {
            // XNU uses the resolved final component for the kernel process
            // name, so a symlink would leave it as rchd. Split-filesystem or
            // protected installations need a private executable copy instead.
            // Prefer the zero-copy hard link, and retire either with its dir.
            copy_executable_alias(executable, alias, &original)
        }
        // In particular, never replace an already existing alias.
        Err(error) => Err(error),
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn copy_executable_alias(
    executable: &Path,
    alias: &Path,
    original: &std::fs::Metadata,
) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut source = std::fs::File::open(executable)?;
    if !same_file(original, &source.metadata()?) {
        return Err(io::Error::other("SSH guardian executable identity changed"));
    }
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(alias)?;
    let copied = io::copy(&mut source, &mut destination)?;
    let after = source.metadata()?;
    if copied != original.len()
        || after.len() != original.len()
        || after.mtime() != original.mtime()
        || after.mtime_nsec() != original.mtime_nsec()
    {
        return Err(io::Error::other(
            "SSH guardian executable changed while copying",
        ));
    }
    destination.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    let installed = std::fs::symlink_metadata(alias)?;
    if !installed.is_file() || !same_file(&installed, &destination.metadata()?) {
        return Err(io::Error::other("SSH guardian executable alias changed"));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

impl DirectoryIdentity {
    fn read(path: &Path) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !path.is_absolute()
            || !path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b"rch-"))
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::other(
                "SSH control directory is not private and owned",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        })
    }

    fn remove(self, path: &Path) -> io::Result<()> {
        if Self::read(path)? != self {
            return Err(io::Error::other(
                "SSH control directory identity changed; retained",
            ));
        }
        // Only this connection's freshly created private TempDir is removed,
        // after its master has been reaped. Never enumerate sibling sockets.
        std::fs::remove_dir_all(path)
    }
}

struct GuardianArguments {
    parent: u32,
    directory: PathBuf,
    identity: DirectoryIdentity,
    program: OsString,
    arguments: Vec<OsString>,
}

impl GuardianArguments {
    fn parse(mut arguments: impl Iterator<Item = OsString>) -> io::Result<Self> {
        fn argument(arguments: &mut impl Iterator<Item = OsString>) -> io::Result<OsString> {
            arguments
                .next()
                .ok_or_else(|| io::Error::other("incomplete SSH guardian invocation"))
        }
        fn number<T: std::str::FromStr>(
            arguments: &mut impl Iterator<Item = OsString>,
        ) -> io::Result<T> {
            argument(arguments)?
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| io::Error::other("invalid SSH guardian identity"))
        }
        Ok(Self {
            parent: number(&mut arguments)?,
            directory: PathBuf::from(argument(&mut arguments)?),
            identity: DirectoryIdentity {
                device: number(&mut arguments)?,
                inode: number(&mut arguments)?,
                uid: number(&mut arguments)?,
            },
            program: argument(&mut arguments)?,
            arguments: arguments.collect(),
        })
    }

    fn validate_directory(&self) -> io::Result<()> {
        if DirectoryIdentity::read(&self.directory)? != self.identity {
            return Err(io::Error::other(
                "SSH control directory changed before guardian startup",
            ));
        }
        Ok(())
    }
}

fn run_guardian(arguments: Vec<OsString>) -> i32 {
    let result = GuardianArguments::parse(arguments.into_iter()).and_then(|arguments| {
        arguments.validate_directory()?;
        // This is a dedicated helper before its runtime or first child.
        let setup = || -> io::Result<tokio::runtime::Runtime> {
            #[cfg(target_os = "linux")]
            rustix::process::set_child_subreaper(Some(rustix::process::Pid::INIT))?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        };
        let runtime = match setup() {
            Ok(runtime) => runtime,
            Err(error) => {
                // No master exists yet. After spawn, teardown errors must
                // retain the directory until reaping has been established.
                let _ = arguments.identity.remove(&arguments.directory);
                return Err(error);
            }
        };
        runtime.block_on(guard_master(arguments))
    });
    match result {
        Ok(result) => {
            use std::io::Write;
            // The diagnostic was copied before the private log was retired.
            // Broken output after parent death must not undo completed cleanup.
            if let Ok(result) = serde_json::to_string(&result) {
                #[cfg(test)]
                let _ = writeln!(std::io::stdout());
                let _ = writeln!(std::io::stdout(), "{RESULT}{result}");
            }
            0
        }
        Err(_) => 1,
    }
}

async fn parent_closed(parent: &tokio::io::unix::AsyncFd<OwnedFd>) -> io::Result<()> {
    let mut byte = [0u8];
    loop {
        // Any input, EOF or read failure revokes ownership. No input frames
        // are sent, and no blocking stdin thread survives normal completion.
        match rustix::io::read(parent.get_ref(), &mut byte) {
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::AGAIN) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        parent.readable().await?.clear_ready();
    }
}

async fn guard_master(arguments: GuardianArguments) -> io::Result<GuardianResult> {
    arguments.validate_directory()?;
    let parent = (|| -> io::Result<tokio::io::unix::AsyncFd<OwnedFd>> {
        let parent = rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3)?;
        let stat = rustix::fs::fstat(&parent)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Fifo {
            return Err(io::Error::other(
                "SSH guardian requires its private parent pipe",
            ));
        }
        let flags = rustix::fs::fcntl_getfl(&parent)?;
        rustix::fs::fcntl_setfl(&parent, flags | rustix::fs::OFlags::NONBLOCK)?;
        tokio::io::unix::AsyncFd::new(parent)
    })();
    let parent = match parent {
        Ok(parent) => parent,
        Err(error) => {
            let _ = arguments.identity.remove(&arguments.directory);
            return Err(error);
        }
    };
    let expected = i32::try_from(arguments.parent)
        .ok()
        .and_then(rustix::process::Pid::from_raw);
    let mut byte = [0u8];
    let initial = rustix::io::read(parent.get_ref(), &mut byte);
    if expected.is_none()
        || rustix::process::getppid() != expected
        || initial != Err(rustix::io::Errno::AGAIN)
    {
        arguments.identity.remove(&arguments.directory)?;
        return Ok(GuardianResult {
            status: 137 << 8,
            diagnostic: "SSH caller exited before master startup".into(),
        });
    }
    let mut command = tokio::process::Command::new(&arguments.program);
    command
        .args(&arguments.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match OwnedProcessGroup::spawn(&mut command) {
        Ok(child) => child,
        Err(error) => {
            arguments.identity.remove(&arguments.directory)?;
            return Err(error);
        }
    };
    #[cfg(target_os = "linux")]
    let group = child
        .unreaped_pid()
        .expect("new master has an unreaped PID");
    let status = tokio::select! {
        biased;
        _ = parent_closed(&parent) => {
            let _ = child.start_kill();
            child.wait().await?
        }
        status = child.wait() => status?,
    };
    // The direct master's PID stayed unreaped until group termination. The
    // dedicated Linux subreaper now owns the ordinary proxy descendants too.
    // Wait only for that group: a deliberately detached proxy is outside this
    // ownership boundary and must not keep the guardian alive indefinitely.
    #[cfg(target_os = "linux")]
    loop {
        match rustix::process::waitpgid(group, rustix::process::WaitOptions::NOHANG) {
            Ok(Some(_)) | Err(rustix::io::Errno::INTR) => {}
            Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            Err(rustix::io::Errno::CHILD) => break,
            Err(error) => return Err(error.into()),
        }
    }
    let diagnostic = super::ssh_connect_diagnostic(&arguments.directory.join("log"));
    arguments.identity.remove(&arguments.directory)?;
    Ok(GuardianResult {
        status: status.into_raw(),
        diagnostic,
    })
}

#[cfg(test)]
mod tests {
    use super::super::OwnedSshProcess;
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    struct Unrelated(std::process::Child);

    impl Drop for Unrelated {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn fixture(root: &Path) -> (Arc<SshControlDir>, tokio::process::Command) {
        let directory = Arc::new(
            SshControlDir::new(
                tempfile::Builder::new()
                    .prefix("rch-")
                    .tempdir_in(root)
                    .unwrap(),
            )
            .unwrap(),
        );
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                r#"printf '%s\n' "$$" > "$1/master-pid"
printf '%s\n' "$PPID" > "$1/guardian-pid"
sleep 60 &
printf '%s\n' "$!" > "$1/proxy-pid"
while [ ! -f "$1/exit" ]; do sleep 0.02; done
exit 37
"#,
                "rch-guardian-fixture",
            ])
            .arg(root);
        (directory, command)
    }

    async fn started(root: &Path) -> [u32; 3] {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let pid = |name| {
                    std::fs::read_to_string(root.join(name))
                        .ok()?
                        .trim()
                        .parse::<u32>()
                        .ok()
                };
                if let (Some(master), Some(proxy), Some(guardian)) =
                    (pid("master-pid"), pid("proxy-pid"), pid("guardian-pid"))
                {
                    #[cfg(target_os = "linux")]
                    assert_eq!(
                        std::fs::read_to_string(format!("/proc/{guardian}/comm"))
                            .unwrap()
                            .trim(),
                        EXECUTABLE_NAME,
                        "name-based rch/rchd termination must exclude the guardian"
                    );
                    return [master, proxy, guardian];
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("guarded master and proxy must really start")
    }

    fn assert_reaped(pids: [u32; 3]) {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let gone = pids.iter().all(|pid| {
                let pid = rustix::process::Pid::from_raw(i32::try_from(*pid).unwrap()).unwrap();
                rustix::process::test_kill_process(pid) == Err(rustix::io::Errno::SRCH)
            });
            if gone {
                return;
            }
            assert!(
                Instant::now() < until,
                "guarded processes remain (including zombies): {pids:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn control_directory_is_made_private_before_handoff() {
        let temporary = tempfile::Builder::new().prefix("rch-").tempdir().unwrap();
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let directory = SshControlDir::new(temporary).unwrap();
        assert_eq!(
            std::fs::metadata(directory.path()).unwrap().mode() & 0o777,
            0o700
        );
        assert!(DirectoryIdentity::read(directory.path()).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn running_image_alias_survives_atomic_executable_replacement() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("owner");
        let alias = root.path().join(EXECUTABLE_NAME);
        // A small disposable native executable keeps this regression separate
        // from the test runner's own image and any concurrently running tests.
        std::fs::copy("/bin/sh", &executable).unwrap();
        create_running_image_alias(&alias).unwrap();
        assert_eq!(
            std::fs::read_link(&alias).unwrap(),
            Path::new("/proc/self/exe")
        );
        let mut owner = Unrelated(
            std::process::Command::new(&executable)
                .args([
                    "-c",
                    r#": > "$1/ready"
while [ ! -f "$1/replaced" ]; do sleep 0.01; done
exec "$1/rch-ssh-guard" -c 'printf "resumed\n" > "$1/resumed"' rch-image-resumed "$1"
"#,
                    "rch-image-owner",
                ])
                .arg(root.path())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !root.path().join("ready").exists() {
            assert!(owner.0.try_wait().unwrap().is_none());
            assert!(
                Instant::now() < deadline,
                "disposable owner failed to start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let replacement = root.path().join("replacement");
        std::fs::write(&replacement, b"#!/bin/sh\nexit 97\n").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&replacement, &executable).unwrap();
        assert!(
            std::fs::read_link(format!("/proc/{}/exe", owner.0.id()))
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .ends_with(b" (deleted)")
        );
        std::fs::write(root.path().join("replaced"), b"continue").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = owner.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "running-image re-exec did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "re-exec must not run the replacement stub: {status}"
        );
        assert_eq!(
            std::fs::read(root.path().join("resumed")).unwrap(),
            b"resumed\n"
        );
    }

    #[test]
    fn executable_hard_link_preserves_installed_file_permissions() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("installed-rchd");
        let alias = root.path().join(EXECUTABLE_NAME);
        std::fs::write(&executable, b"private fixture executable").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        let original = std::fs::metadata(&executable).unwrap();
        create_executable_alias(&executable, &alias).unwrap();
        assert!(same_file(
            &original,
            &std::fs::symlink_metadata(&alias).unwrap()
        ));
        assert_eq!(std::fs::metadata(executable).unwrap().mode() & 0o777, 0o500);
    }

    #[test]
    fn executable_alias_never_replaces_an_existing_path() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("installed-rchd");
        let alias = root.path().join(EXECUTABLE_NAME);
        std::fs::write(&executable, b"source executable").unwrap();
        std::fs::write(&alias, b"must survive").unwrap();
        assert_eq!(
            create_executable_alias(&executable, &alias)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            create_running_image_alias(&alias).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(alias).unwrap(), b"must survive");
    }

    #[test]
    fn executable_copy_is_private_complete_and_never_overwrites() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("installed-rchd");
        let alias = root.path().join(EXECUTABLE_NAME);
        let bytes: Vec<u8> = (0..=255).cycle().take(17 * 1024).collect();
        std::fs::write(&executable, &bytes).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        let original = std::fs::metadata(&executable).unwrap();
        copy_executable_alias(&executable, &alias, &original).unwrap();
        let copied = std::fs::symlink_metadata(&alias).unwrap();
        assert!(copied.is_file());
        assert!(!same_file(&original, &copied));
        assert_eq!(copied.mode() & 0o777, 0o700);
        assert_eq!(std::fs::read(&alias).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&executable).unwrap().mode() & 0o777,
            0o500
        );
        assert_eq!(
            copy_executable_alias(&executable, &alias, &original)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(alias).unwrap(), bytes);
    }

    #[test]
    fn runtime_shutdown_reaps_master_proxy_and_guardian_without_harming_other_children() {
        let root = tempfile::tempdir().unwrap();
        let (directory, mut command) = fixture(root.path());
        let control_path = directory.path().to_owned();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (process, pids) = runtime.block_on(async {
            let process = OwnedSshProcess::spawn(&mut command, Some(directory), None).unwrap();
            let pids = started(root.path()).await;
            (process, pids)
        });
        // Spawn after the lifetime writer exists. It must not inherit that
        // writer and keep the master alive after this runtime disappears.
        let mut unrelated = Unrelated(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap(),
        );
        drop(runtime);
        assert_reaped(pids);
        assert!(
            !control_path.exists(),
            "the independent helper retires its private directory"
        );
        assert!(unrelated.0.try_wait().unwrap().is_none());
        drop(process);
    }

    #[tokio::test]
    async fn guarded_natural_master_exit_preserves_status_and_reaps_ordinary_proxy() {
        let root = tempfile::tempdir().unwrap();
        let (directory, mut command) = fixture(root.path());
        let control_path = directory.path().to_owned();
        let process = OwnedSshProcess::spawn(&mut command, Some(directory), None).unwrap();
        let pids = started(root.path()).await;
        std::fs::write(root.path().join("exit"), b"exit").unwrap();
        assert_eq!(
            process
                .wait_until(tokio::time::Instant::now() + Duration::from_secs(5))
                .await
                .unwrap()
                .code(),
            Some(37)
        );
        assert_reaped(pids);
        assert!(!control_path.exists());
    }

    #[tokio::test]
    async fn guarded_cleanup_preserves_substituted_control_directory() {
        let root = tempfile::tempdir().unwrap();
        let (directory, mut command) = fixture(root.path());
        let control_path = directory.path().to_owned();
        let mut process = OwnedSshProcess::spawn(&mut command, Some(directory), None).unwrap();
        let pids = started(root.path()).await;
        let retained = root.path().join("retained-original");
        std::fs::rename(&control_path, &retained).unwrap();
        std::fs::create_dir(&control_path).unwrap();
        std::fs::set_permissions(&control_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(control_path.join("unowned"), b"must survive").unwrap();
        process
            .stop_before(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(
            process
                .wait_until(tokio::time::Instant::now() + Duration::from_secs(5))
                .await
                .is_err()
        );
        assert_reaped(pids);
        assert_eq!(
            std::fs::read(control_path.join("unowned")).unwrap(),
            b"must survive"
        );
        assert!(
            retained.is_dir(),
            "a renamed control directory is retained, never searched for"
        );
    }

    #[tokio::test]
    async fn guarded_master_spawn_failure_retires_private_directory_without_fallback() {
        let root = tempfile::tempdir().unwrap();
        let directory = Arc::new(
            SshControlDir::new(
                tempfile::Builder::new()
                    .prefix("rch-")
                    .tempdir_in(root.path())
                    .unwrap(),
            )
            .unwrap(),
        );
        let control_path = directory.path().to_owned();
        let mut command = tokio::process::Command::new(root.path().join("missing-ssh"));
        let process = OwnedSshProcess::spawn(&mut command, Some(directory), None).unwrap();
        assert!(
            process
                .wait_until(tokio::time::Instant::now() + Duration::from_secs(5))
                .await
                .is_err()
        );
        assert!(!control_path.exists());
    }

    #[test]
    fn invalid_lifetime_pipe_retires_private_directory_before_starting_master() {
        let root = tempfile::tempdir().unwrap();
        let (directory, master) = fixture(root.path());
        let identity = DirectoryIdentity::read(directory.path()).unwrap();
        let mut arguments = vec![
            OsString::from(std::process::id().to_string()),
            directory.path().as_os_str().to_owned(),
            OsString::from(identity.device.to_string()),
            OsString::from(identity.inode.to_string()),
            OsString::from(identity.uid.to_string()),
            master.as_std().get_program().to_owned(),
        ];
        arguments.extend(master.as_std().get_args().map(std::ffi::OsStr::to_owned));
        let status = helper_command(arguments, directory.path())
            .unwrap()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .as_std_mut()
            .status()
            .unwrap();
        assert!(!status.success(), "invalid lifetime input is rejected");
        assert!(!directory.path().exists());
        assert!(!root.path().join("master-pid").exists());
    }

    #[test]
    #[ignore = "isolated helper for SSH master lifetime tests"]
    fn guardian_child() {
        use std::os::unix::ffi::OsStringExt;
        let encoded = std::env::var("RCH_TEST_SSH_GUARDIAN_ARGUMENTS").unwrap();
        let arguments: Vec<Vec<u8>> = serde_json::from_str(&encoded).unwrap();
        std::process::exit(run_guardian(
            arguments.into_iter().map(OsString::from_vec).collect(),
        ));
    }
}
