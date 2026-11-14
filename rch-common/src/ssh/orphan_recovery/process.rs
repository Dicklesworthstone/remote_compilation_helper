//! Conservative process evidence for a listener already bound by peer credentials.
//!
//! PPID 1 alone is insufficient: an intentionally backgrounded SSH master also
//! has that parent. Recognize only RCH's explicit foreground invocation, and
//! fence every inspection with the process's kernel birth marker. This module
//! never signals a PID and never decides which socket to connect to.

use crate::process_identity::ProcessStart;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", test))]
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use tokio::time::Instant;

const RECORD_LIMIT: usize = 64 * 1024;
const ARGUMENT_LIMIT: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) uid: u32,
    // The caller keeps one connected socket throughout both inspections. It
    // cannot survive a reboot, so the kernel birth marker suffices here; Darwin
    // need not launch an unbounded sysctl to discover a boot UUID.
    pub(super) birth: ProcessStart,
}

pub(super) async fn inspect(pid: u32, socket: &Path, deadline: Instant) -> Option<Identity> {
    let uid = rustix::process::getuid().as_raw();
    if pid <= 1
        || i32::try_from(pid).is_err()
        || uid != rustix::process::geteuid().as_raw()
        || Instant::now() >= deadline
    {
        return None;
    }
    inspect_platform(pid, uid, socket, deadline).await
}

#[cfg(target_os = "linux")]
async fn inspect_platform(
    pid: u32,
    uid: u32,
    socket: &Path,
    deadline: Instant,
) -> Option<Identity> {
    use crate::process_identity::{ProcessObservation, observe_process};

    // The shared observer verifies that /proc belongs to our PID namespace.
    // Inspect only our live process here: observing an arbitrary candidate may
    // synchronously enumerate thousands of threads when its leader is zombie.
    // Candidate evidence below comes from two bounded, complete proc records.
    let ProcessObservation::Present(before) = observe_process(std::process::id()) else {
        return None;
    };
    linux_init_parent(deadline).await?;
    let process = std::path::PathBuf::from(format!("/proc/{pid}"));
    let first = linux_snapshot(&process, pid, uid, deadline).await?;
    let executable = tokio::time::timeout_at(deadline, tokio::fs::read_link(process.join("exe")))
        .await
        .ok()?
        .ok()?;
    if !ssh_executable(&executable) {
        return None;
    }
    let cmdline = read_bounded(&process.join("cmdline"), deadline).await?;
    let arguments = nul_arguments(&cmdline)?;
    if !rch_foreground_arguments(&arguments, socket) {
        return None;
    }
    let second = linux_snapshot(&process, pid, uid, deadline).await?;
    if Instant::now() >= deadline {
        return None;
    }
    let ProcessObservation::Present(after) = observe_process(std::process::id()) else {
        return None;
    };
    (Instant::now() < deadline && first == second && before == after).then_some(second)
}

#[cfg(target_os = "linux")]
async fn linux_init_parent(deadline: Instant) -> Option<()> {
    use std::os::unix::fs::MetadataExt;

    // PID 1 can be a live application inside a container, including another
    // RCH owner. PPID 1 is orphan evidence only when the parent is a verified
    // system init. Unknown or unreadable PID 1 executables are not authority
    // to drain a connection, even when their UID differs from the child.
    let status = read_bounded(Path::new("/proc/1/status"), deadline).await?;
    let executable = tokio::time::timeout_at(deadline, tokio::fs::read_link("/proc/1/exe"))
        .await
        .ok()?
        .ok()?;
    let metadata = tokio::time::timeout_at(deadline, tokio::fs::metadata("/proc/1/exe"))
        .await
        .ok()?
        .ok()?;
    (known_linux_init(std::str::from_utf8(&status).ok()?, &executable)
        && metadata.is_file()
        && metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && Instant::now() < deadline)
        .then_some(())
}

#[cfg(any(target_os = "linux", test))]
fn known_linux_init(status: &str, executable: &Path) -> bool {
    status_number(status, "Pid:") == Some(1)
        && status_number(status, "PPid:") == Some(0)
        && status_has_uid(status, 0)
        && matches!(
            executable.to_str(),
            Some(
                "/usr/lib/systemd/systemd"
                    | "/lib/systemd/systemd"
                    | "/sbin/init"
                    | "/usr/sbin/init"
                    | "/sbin/openrc-init"
                    | "/usr/sbin/openrc-init"
            )
        )
}

#[cfg(target_os = "linux")]
async fn linux_snapshot(process: &Path, pid: u32, uid: u32, deadline: Instant) -> Option<Identity> {
    let stat = read_bounded(&process.join("stat"), deadline).await?;
    let status = read_bounded(&process.join("status"), deadline).await?;
    let stat = std::str::from_utf8(&stat).ok()?;
    let birth = ProcessStart::Linux {
        ticks: linux_orphan_ticks(stat, pid)?,
    };
    linux_records(pid, uid, &birth, stat, std::str::from_utf8(&status).ok()?)
}

#[cfg(any(target_os = "linux", test))]
async fn read_bounded(path: &Path, deadline: Instant) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    if Instant::now() >= deadline {
        return None;
    }
    tokio::time::timeout_at(deadline, async {
        let file = tokio::fs::File::open(path).await.ok()?;
        let mut bytes = Vec::new();
        file.take((RECORD_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        (bytes.len() <= RECORD_LIMIT).then_some(bytes)
    })
    .await
    .ok()?
}

#[cfg(any(target_os = "linux", test))]
fn linux_records(
    pid: u32,
    uid: u32,
    birth: &ProcessStart,
    stat: &str,
    status: &str,
) -> Option<Identity> {
    let ProcessStart::Linux { ticks } = birth else {
        return None;
    };
    if linux_orphan_ticks(stat, pid) != Some(*ticks)
        || status_number(status, "Pid:") != Some(u64::from(pid))
        || status_number(status, "PPid:") != Some(1)
    {
        return None;
    }
    if !status_has_uid(status, uid) {
        return None;
    }
    Some(Identity {
        pid,
        uid,
        birth: birth.clone(),
    })
}

#[cfg(any(target_os = "linux", test))]
fn status_has_uid(status: &str, uid: u32) -> bool {
    let mut records = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let Some(record) = records.next() else {
        return false;
    };
    let mut ids = record.split_ascii_whitespace();
    records.next().is_none()
        && (0..4).all(|_| ids.next().and_then(decimal) == Some(u64::from(uid)))
        && ids.next().is_none()
}

#[cfg(any(target_os = "linux", test))]
fn linux_orphan_ticks(stat: &str, pid: u32) -> Option<u64> {
    // comm may contain spaces and ')' characters; only the final ') ' ends it.
    let (prefix, rest) = stat.rsplit_once(") ")?;
    if decimal(prefix.split_once(" (")?.0) != Some(u64::from(pid)) {
        return None;
    }
    let mut fields = rest.split_ascii_whitespace();
    if !matches!(
        fields.next()?,
        "R" | "S" | "D" | "T" | "t" | "K" | "W" | "P" | "I"
    ) || decimal(fields.next()?) != Some(1)
    {
        return None;
    }
    // Having consumed state (field 3) and PPID (4), starttime is field 22.
    fields.nth(17).and_then(decimal)
}

#[cfg(any(target_os = "linux", test))]
fn status_number(status: &str, name: &str) -> Option<u64> {
    let mut records = status.lines().filter_map(|line| line.strip_prefix(name));
    let mut fields = records.next()?.split_ascii_whitespace();
    let value = decimal(fields.next()?)?;
    (records.next().is_none() && fields.next().is_none()).then_some(value)
}

#[cfg(target_os = "macos")]
async fn inspect_platform(
    pid: u32,
    uid: u32,
    socket: &Path,
    deadline: Instant,
) -> Option<Identity> {
    let first = darwin_snapshot(pid, uid)?;
    let executable = libproc::proc_pid::pidpath(i32::try_from(pid).ok()?).ok()?;
    if !ssh_executable(Path::new(&executable)) {
        return None;
    }
    // libproc exposes birth/parent/UID/executable but not an argv API. ps is
    // display text, so refuse whitespace/quoting ambiguity instead of applying
    // shell parsing or treating a command-name match as ownership evidence.
    let mut command = tokio::process::Command::new("/bin/ps");
    command.args(["-ww", "-p", &pid.to_string(), "-o", "command="]);
    command.env("LC_ALL", "C");
    let output =
        super::super::capture_control_output(&mut command, None, RECORD_LIMIT, 4096, deadline)
            .await
            .ok()?;
    if !output.status.success() || !output.stderr.is_empty() {
        return None;
    }
    let arguments = darwin_arguments(&output.stdout, socket)?;
    if !rch_foreground_arguments(&arguments, socket) {
        return None;
    }
    let second = darwin_snapshot(pid, uid)?;
    (Instant::now() < deadline && first == second).then_some(second)
}

#[cfg(target_os = "macos")]
fn darwin_snapshot(pid: u32, uid: u32) -> Option<Identity> {
    let info =
        libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(i32::try_from(pid).ok()?, 0)
            .ok()?;
    if info.pbi_pid != pid
        || info.pbi_ppid != 1
        || !matches!(info.pbi_status, 1..=4)
        || info.pbi_uid != uid
        || info.pbi_ruid != uid
        || info.pbi_svuid != uid
        || info.pbi_start_tvsec == 0
        || info.pbi_start_tvusec >= 1_000_000
    {
        return None;
    }
    Some(Identity {
        pid,
        uid,
        birth: ProcessStart::Darwin {
            seconds: info.pbi_start_tvsec,
            microseconds: u32::try_from(info.pbi_start_tvusec).ok()?,
        },
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn inspect_platform(
    _pid: u32,
    _uid: u32,
    _socket: &Path,
    _deadline: Instant,
) -> Option<Identity> {
    None
}

fn ssh_executable(path: &Path) -> bool {
    path.is_absolute() && path.file_name() == Some(OsStr::new("ssh"))
}

#[cfg(any(target_os = "linux", test))]
fn nul_arguments(bytes: &[u8]) -> Option<Vec<OsString>> {
    let bytes = bytes.strip_suffix(&[0])?;
    let arguments: Vec<_> = bytes.split(|byte| *byte == 0).collect();
    if arguments.len() > ARGUMENT_LIMIT || arguments.iter().any(|argument| argument.is_empty()) {
        return None;
    }
    Some(
        arguments
            .into_iter()
            .map(|argument| OsString::from_vec(argument.to_vec()))
            .collect(),
    )
}

#[cfg(any(target_os = "macos", test))]
fn darwin_arguments(bytes: &[u8], socket: &Path) -> Option<Vec<OsString>> {
    let command = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    if socket
        .as_os_str()
        .as_bytes()
        .iter()
        .any(|byte| byte.is_ascii_whitespace() || matches!(*byte, b'\\' | b'\'' | b'"'))
        || command
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'\'' | b'"'))
    {
        return None;
    }
    let arguments: Vec<_> = command
        .split_ascii_whitespace()
        .map(OsString::from)
        .collect();
    (arguments.len() <= ARGUMENT_LIMIT).then_some(arguments)
}

fn decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn numeric_option(value: &OsStr, prefix: &str, nonzero: bool) -> bool {
    value
        .to_str()
        .and_then(|value| value.strip_prefix(prefix))
        .and_then(decimal)
        .is_some_and(|number| !nonzero || number > 0)
}

fn rch_foreground_arguments(arguments: &[OsString], socket: &Path) -> bool {
    recognize_arguments(arguments, socket).is_some()
}

fn recognize_arguments(arguments: &[OsString], socket: &Path) -> Option<()> {
    if !socket.is_absolute()
        || socket.file_name() != Some(OsStr::new("master"))
        || arguments.len() > ARGUMENT_LIMIT
    {
        return None;
    }
    let log = socket.parent()?.join("log");
    let mut arguments = arguments.iter();
    if Path::new(arguments.next()?).file_name() != Some(OsStr::new("ssh")) {
        return None;
    }
    // Match the layout emitted by SshClient::master_command. No unknown options
    // or duplicate settings are accepted: OpenSSH uses the FIRST value, so a
    // later ControlPersist=no cannot undo an earlier backgrounding directive.
    for expected in [
        OsStr::new("-E"),
        log.as_os_str(),
        OsStr::new("-S"),
        socket.as_os_str(),
        OsStr::new("-M"),
        OsStr::new("-N"),
        OsStr::new("-T"),
        OsStr::new("-o"),
        OsStr::new("BatchMode=yes"),
        OsStr::new("-o"),
        OsStr::new("ConnectionAttempts=1"),
        OsStr::new("-o"),
        OsStr::new("ControlPersist=no"),
        OsStr::new("-o"),
    ] {
        if arguments.next()?.as_os_str() != expected {
            return None;
        }
    }
    if !matches!(
        arguments.next()?.to_str()?,
        "StrictHostKeyChecking=yes"
            | "StrictHostKeyChecking=accept-new"
            | "StrictHostKeyChecking=no"
    ) || arguments.next()? != "-o"
        || !numeric_option(arguments.next()?, "ConnectTimeout=", true)
        || arguments.next()? != "-o"
        || arguments.next()? != "ForkAfterAuthentication=no"
    {
        return None;
    }
    if arguments
        .as_slice()
        .first()
        .is_some_and(|argument| argument == "-o")
    {
        arguments.next();
        if !numeric_option(arguments.next()?, "ServerAliveInterval=", false) {
            return None;
        }
    }
    if arguments
        .as_slice()
        .first()
        .is_some_and(|argument| argument == "-i")
    {
        arguments.next();
        if arguments.next()?.is_empty()
            || arguments.next()? != "-o"
            || arguments.next()? != "IdentitiesOnly=yes"
        {
            return None;
        }
    }
    let destination = arguments.next()?.as_bytes();
    if destination.is_empty()
        || destination[0] == b'-'
        || destination.iter().any(u8::is_ascii_whitespace)
        || arguments.next().is_some()
    {
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn invocation(socket: &Path) -> Vec<OsString> {
        let mut arguments: Vec<OsString> = ["/usr/bin/ssh", "-E"].map(OsString::from).into();
        arguments.push(socket.parent().unwrap().join("log").into_os_string());
        arguments.push("-S".into());
        arguments.push(socket.as_os_str().to_owned());
        arguments.extend(
            [
                "-M",
                "-N",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "ControlPersist=no",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ForkAfterAuthentication=no",
                "builder@worker",
            ]
            .map(OsString::from),
        );
        arguments
    }

    #[test]
    fn recognizes_commands_from_the_actual_master_builder() {
        use crate::ssh::{KnownHostsPolicy, SshClient, SshOptions};
        use crate::types::WorkerConfig;

        let directory = tempfile::tempdir().unwrap();
        let identity = directory.path().join("identity key");
        std::fs::write(&identity, "argument recognition fixture").unwrap();
        let socket = directory.path().join("master");
        for known_hosts in [
            KnownHostsPolicy::Strict,
            KnownHostsPolicy::Add,
            KnownHostsPolicy::AcceptAll,
        ] {
            for optional in [false, true] {
                let client = SshClient::new(
                    WorkerConfig {
                        identity_file: if optional {
                            identity.to_str().unwrap().to_owned()
                        } else {
                            directory
                                .path()
                                .join("absent-key")
                                .to_str()
                                .unwrap()
                                .to_owned()
                        },
                        ..WorkerConfig::default()
                    },
                    SshOptions {
                        known_hosts,
                        server_alive_interval: optional.then_some(Duration::ZERO),
                        ..SshOptions::default()
                    },
                );
                for explicit_foreground in [true, false] {
                    let command = client.master_command(
                        Path::new("/usr/bin/ssh"),
                        "builder@worker",
                        &socket,
                        &directory.path().join("log"),
                        explicit_foreground,
                    );
                    let command = command.as_std();
                    let arguments: Vec<_> = std::iter::once(command.get_program())
                        .chain(command.get_args())
                        .map(OsStr::to_owned)
                        .collect();
                    assert_eq!(
                        rch_foreground_arguments(&arguments, &socket),
                        explicit_foreground
                    );
                }
            }
        }
    }

    #[test]
    fn recognizes_exact_foreground_master_and_optional_identity_and_keepalive() {
        let socket = Path::new("/home/user/.ssh/rch/rch-test/master");
        let mut arguments = invocation(socket);
        assert!(rch_foreground_arguments(&arguments, socket));
        let destination = arguments.pop().unwrap();
        arguments.extend(
            [
                "-o",
                "ServerAliveInterval=0",
                "-i",
                "/home/user/id key",
                "-o",
                "IdentitiesOnly=yes",
            ]
            .map(OsString::from),
        );
        arguments.push(destination);
        assert!(rch_foreground_arguments(&arguments, socket));
        let with_spaces = Path::new("/home/a user/.ssh/rch/rch-test/master");
        assert!(rch_foreground_arguments(
            &invocation(with_spaces),
            with_spaces
        ));
    }

    #[test]
    fn refuses_backgrounding_conflicting_options_passengers_and_wrong_paths() {
        let socket = Path::new("/home/user/.ssh/rch/rch-test/master");
        for replacement in [
            "ControlPersist=yes",
            "ControlPersist=60",
            "ForkAfterAuthentication=yes",
        ] {
            let mut arguments = invocation(socket);
            let prefix = replacement.split_once('=').unwrap().0;
            let argument = arguments
                .iter_mut()
                .find(|arg| arg.to_str().unwrap().starts_with(prefix))
                .unwrap();
            *argument = replacement.into();
            assert!(
                !rch_foreground_arguments(&arguments, socket),
                "{replacement}"
            );
        }
        for extra in ["-f", "-O", "exit", "hostname"] {
            let mut arguments = invocation(socket);
            arguments.push(extra.into());
            assert!(!rch_foreground_arguments(&arguments, socket), "{extra}");
        }
        let mut conflicting = invocation(socket);
        conflicting.splice(
            1..1,
            [OsString::from("-o"), OsString::from("ControlPersist=yes")],
        );
        assert!(!rch_foreground_arguments(&conflicting, socket));
        let mut no_explicit_foreground = invocation(socket);
        no_explicit_foreground.drain(18..20);
        assert!(!rch_foreground_arguments(&no_explicit_foreground, socket));
        let mut wrong_log = invocation(socket);
        wrong_log[2] = "/another/directory/log".into();
        assert!(!rch_foreground_arguments(&wrong_log, socket));
        assert!(!rch_foreground_arguments(
            &invocation(socket),
            Path::new("/other/rch-test/master")
        ));
        assert!(!rch_foreground_arguments(
            &invocation(socket),
            Path::new("relative/master")
        ));
    }

    #[test]
    fn proc_cmdline_requires_complete_nul_delimited_arguments() {
        assert_eq!(nul_arguments(b"ssh\0-a b\0").unwrap(), ["ssh", "-a b"]);
        assert!(nul_arguments(b"ssh\0-a").is_none());
        assert!(nul_arguments(b"ssh\0\0").is_none());
        assert!(nul_arguments(b"").is_none());
        assert!(nul_arguments(&b"a\0".repeat(ARGUMENT_LIMIT + 1)).is_none());
    }

    #[test]
    fn darwin_display_requires_one_unambiguous_complete_command() {
        let socket = Path::new("/home/user/.ssh/rch/rch-test/master");
        let rendered = invocation(socket)
            .iter()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let good = format!("{rendered}\n");
        assert!(rch_foreground_arguments(
            &darwin_arguments(good.as_bytes(), socket).unwrap(),
            socket
        ));
        for bad in [
            rendered,
            format!("{good}{good}"),
            format!("'{good}"),
            format!("{good}\0"),
        ] {
            assert!(darwin_arguments(bad.as_bytes(), socket).is_none());
        }
        assert!(darwin_arguments(good.as_bytes(), Path::new("/home/a user/rch/master")).is_none());
    }

    fn records(parent: u32, state: &str, ticks: u64, uid: u32) -> (String, String) {
        let mut fields = vec![state.to_owned(), parent.to_string()];
        fields.extend((5..22).map(|_| "0".to_owned()));
        fields.push(ticks.to_string());
        (
            format!("42 (ssh ) unusual) {}", fields.join(" ")),
            format!("Pid:\t42\nPPid:\t{parent}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )
    }

    #[test]
    fn linux_pid_one_must_be_a_known_system_init_not_a_live_application_owner() {
        let status = "Name:\tsystemd\nPid:\t1\nPPid:\t0\nUid:\t0\t0\t0\t0\n";
        for path in [
            "/usr/lib/systemd/systemd",
            "/lib/systemd/systemd",
            "/sbin/init",
            "/sbin/openrc-init",
        ] {
            assert!(known_linux_init(status, Path::new(path)), "{path}");
        }
        // Neither a forged comm name nor another UID identifies an adopting
        // init; an RCH owner running as PID 1 must keep its live masters.
        for path in [
            "/usr/bin/rchd",
            "/usr/bin/rch",
            "/tmp/systemd",
            "/usr/bin/tini",
            "/usr/lib/systemd/systemd (deleted)",
        ] {
            assert!(!known_linux_init(status, Path::new(path)), "{path}");
        }
        let path = Path::new("/usr/lib/systemd/systemd");
        for invalid in [
            status.replace("Pid:\t1", "Pid:\t2"),
            status.replace("PPid:\t0", "PPid:\t1"),
            status.replace("Uid:\t0\t0\t0\t0", "Uid:\t1000\t1000\t1000\t1000"),
            status.replace("Uid:\t0\t0\t0\t0", "Uid:\t0\t1000\t0\t0"),
            format!("{status}Uid:\t0\t0\t0\t0\n"),
        ] {
            assert!(!known_linux_init(&invalid, path));
        }
    }

    #[test]
    fn linux_process_evidence_requires_exact_birth_parent_and_all_uids() {
        let birth = ProcessStart::Linux { ticks: 123 };
        let (stat, status) = records(1, "S", 123, 1000);
        assert_eq!(
            linux_records(42, 1000, &birth, &stat, &status),
            Some(Identity {
                pid: 42,
                uid: 1000,
                birth: birth.clone()
            })
        );
        for (parent, state, ticks, uid) in [
            (2, "S", 123, 1000),
            (1, "Z", 123, 1000),
            (1, "S", 124, 1000),
            (1, "S", 123, 1001),
        ] {
            let (stat, status) = records(parent, state, ticks, uid);
            assert!(linux_records(42, 1000, &birth, &stat, &status).is_none());
        }
        assert!(linux_records(43, 1000, &birth, &stat, &status).is_none());
        assert!(
            linux_records(
                42,
                1000,
                &birth,
                &stat,
                &format!("{status}Uid:\t1000 1000 1000 1000\n")
            )
            .is_none()
        );
        assert!(
            linux_records(
                42,
                1000,
                &birth,
                &stat,
                &status.replace("1000\t1000", "1000\t0")
            )
            .is_none()
        );
        assert!(linux_records(42, 1000, &birth, &stat, &format!("{status}PPid:\t1\n")).is_none());
    }

    #[tokio::test]
    async fn bounded_process_reads_refuse_oversize_and_expired_observations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        std::fs::write(&path, vec![b'x'; RECORD_LIMIT + 1]).unwrap();
        assert!(
            read_bounded(&path, Instant::now() + Duration::from_secs(1))
                .await
                .is_none()
        );
        std::fs::write(&path, b"complete").unwrap();
        assert_eq!(
            read_bounded(&path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap(),
            b"complete"
        );
        assert!(read_bounded(&path, Instant::now()).await.is_none());
    }

    #[tokio::test]
    async fn unrelated_live_process_and_invalid_pids_are_never_adopted() {
        let socket = Path::new("/unrelated/rch-test/master");
        let deadline = Instant::now() + Duration::from_secs(1);
        for pid in [0, 1, u32::MAX, std::process::id()] {
            assert!(inspect(pid, socket, deadline).await.is_none());
        }
        assert!(
            inspect(std::process::id(), socket, Instant::now())
                .await
                .is_none()
        );
    }
}
