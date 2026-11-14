//! Recover foreground RCH ControlMasters left behind by pre-guardian daemons.
//!
//! A pathname or a reported PID is not authority to kill a process. Recovery
//! binds an owned directory/socket to the kernel's peer credentials, a stable
//! orphan process identity, and the OpenSSH mux ALIVE reply. It then requests
//! STOP_LISTENING on that same connection. Existing passenger sessions drain;
//! no PID is signalled, and no legacy files or directories are removed.

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout_at};
use tracing::{debug, info};

mod process;

const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(1);
const BATCH_DURATION: Duration = Duration::from_secs(2);
const BATCH_ENTRIES: usize = 128;
const MAX_PACKET: usize = 4096;
const MUX_HELLO: u32 = 0x0000_0001;
const MUX_ALIVE_CHECK: u32 = 0x1000_0004;
const MUX_STOP_LISTENING: u32 = 0x1000_0009;
const MUX_OK: u32 = 0x8000_0001;
const MUX_ALIVE: u32 = 0x8000_0005;
const ALIVE_REQUEST: u32 = 1;
const STOP_REQUEST: u32 = 2;

/// Start bounded recovery of orphaned foreground RCH SSH connections.
///
/// Only the normal daemon should run this task. Isolated test/worker pools must
/// not reconcile the operator's shared SSH directory. Abort the returned task
/// during daemon shutdown; dropping a probe never terminates an SSH process.
pub fn start_ssh_orphan_recovery() -> JoinHandle<()> {
    tokio::spawn(recover_loop(super::ssh_control_directory()))
}

async fn recover_loop(path: PathBuf) {
    loop {
        if let Err(error) = recover_pass(&path).await {
            debug!(%error, "SSH orphan recovery pass could not finish");
        }
        sleep(SCAN_INTERVAL).await;
    }
}

async fn recover_pass(path: &Path) -> io::Result<()> {
    let root = match Directory::open(path) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut entries = tokio::fs::read_dir(path).await?;
    let mut batch_start = Instant::now();
    let mut batch_entries = 0;
    // Keep the iterator across batches. Restarting at the beginning after a
    // time budget would let a few unresponsive sockets starve later orphans.
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if managed_directory_name(&name) {
            match Candidate::open(&root, name) {
                Ok(candidate) => {
                    if let Err(error) = recover_candidate(&candidate).await {
                        debug!(socket = %candidate.socket.display(), %error,
                            "SSH orphan probe declined");
                    }
                }
                // Empty directories, removed sockets and symlinks are not
                // recovery candidates. Leave all remnants to their owners.
                Err(error) => debug!(%error, "SSH orphan candidate unavailable"),
            }
        }
        batch_entries += 1;
        if batch_entries >= BATCH_ENTRIES || batch_start.elapsed() >= BATCH_DURATION {
            sleep(Duration::from_millis(25)).await;
            batch_entries = 0;
            batch_start = Instant::now();
        }
    }
    Ok(())
}

fn managed_directory_name(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix("rch-"))
        .is_some_and(|suffix| {
            (6..=64).contains(&suffix.len())
                && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

struct FileIdentity(rustix::fs::Stat);

impl FileIdentity {
    fn require_owned_type(stat: rustix::fs::Stat, kind: FileType) -> io::Result<Self> {
        if FileType::from_raw_mode(stat.st_mode) != kind
            || stat.st_uid != rustix::process::getuid().as_raw()
            || stat.st_mode & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSH recovery requires an owned, non-writable directory or socket",
            ));
        }
        Ok(Self(stat))
    }

    fn matches(&self, other: &rustix::fs::Stat) -> bool {
        self.0.st_dev == other.st_dev
            && self.0.st_ino == other.st_ino
            && self.0.st_uid == other.st_uid
            && self.0.st_mode == other.st_mode
    }
}

struct Directory {
    fd: OwnedFd,
    identity: FileIdentity,
    path: PathBuf,
}

impl Directory {
    fn flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
    }

    fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH recovery root must be absolute",
            ));
        }
        let fd = rustix::fs::open(path, Self::flags(), Mode::empty())?;
        Self::from_fd(fd, path.to_path_buf())
    }

    fn child(&self, name: &OsStr) -> io::Result<Self> {
        let fd = rustix::fs::openat(&self.fd, name, Self::flags(), Mode::empty())?;
        Self::from_fd(fd, self.path.join(name))
    }

    fn from_fd(fd: OwnedFd, path: PathBuf) -> io::Result<Self> {
        let identity =
            FileIdentity::require_owned_type(rustix::fs::fstat(&fd)?, FileType::Directory)?;
        Ok(Self { fd, identity, path })
    }

    fn revalidate(&self) -> io::Result<()> {
        require_same(&self.identity, rustix::fs::fstat(&self.fd)?)?;
        require_same(
            &self.identity,
            rustix::fs::statat(rustix::fs::CWD, &self.path, AtFlags::SYMLINK_NOFOLLOW)?,
        )
    }
}

fn require_same(expected: &FileIdentity, observed: rustix::fs::Stat) -> io::Result<()> {
    if expected.matches(&observed) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SSH recovery path identity changed",
        ))
    }
}

struct Candidate<'a> {
    root: &'a Directory,
    name: OsString,
    directory: Directory,
    socket_identity: FileIdentity,
    socket: PathBuf,
}

impl<'a> Candidate<'a> {
    fn open(root: &'a Directory, name: OsString) -> io::Result<Self> {
        if !managed_directory_name(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Not an RCH directory",
            ));
        }
        root.revalidate()?;
        let directory = root.child(&name)?;
        let socket_identity = FileIdentity::require_owned_type(
            rustix::fs::statat(&directory.fd, "master", AtFlags::SYMLINK_NOFOLLOW)?,
            FileType::Socket,
        )?;
        let socket = directory.path.join("master");
        Ok(Self {
            root,
            name,
            directory,
            socket_identity,
            socket,
        })
    }

    fn revalidate(&self) -> io::Result<()> {
        self.root.revalidate()?;
        self.directory.revalidate()?;
        require_same(
            &self.directory.identity,
            rustix::fs::statat(&self.root.fd, &self.name, AtFlags::SYMLINK_NOFOLLOW)?,
        )?;
        require_same(
            &self.socket_identity,
            rustix::fs::statat(&self.directory.fd, "master", AtFlags::SYMLINK_NOFOLLOW)?,
        )
    }
}

async fn recover_candidate(candidate: &Candidate<'_>) -> io::Result<bool> {
    let deadline = Instant::now() + CANDIDATE_TIMEOUT;
    timeout_at(deadline, async {
        candidate.revalidate()?;
        let mut stream = UnixStream::connect(&candidate.socket).await?;
        let credentials = stream.peer_cred()?;
        if credentials.uid() != rustix::process::getuid().as_raw() {
            return Ok(false);
        }
        let Some(pid) = credentials.pid().and_then(|pid| u32::try_from(pid).ok()) else {
            return Ok(false);
        };
        let Some(identity) = process::inspect(pid, &candidate.socket, deadline).await else {
            return Ok(false);
        };
        // The ALIVE reply must agree with the kernel, not merely name a live
        // process. Keep this stream all the way through STOP_LISTENING.
        check_master(&mut stream, pid).await?;
        if process::inspect(pid, &candidate.socket, deadline).await.as_ref() != Some(&identity) {
            return Ok(false);
        }
        candidate.revalidate()?;
        stop_listening(&mut stream).await?;
        info!(pid, socket = %candidate.socket.display(), "Requested drain of orphaned RCH SSH master");
        Ok(true)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH orphan probe deadline exceeded"))?
}

fn invalid_packet() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Unexpected OpenSSH mux response",
    )
}

async fn write_packet<S: AsyncWrite + Unpin>(stream: &mut S, words: &[u32]) -> io::Result<()> {
    stream
        .write_u32(u32::try_from(words.len() * 4).map_err(|_| invalid_packet())?)
        .await?;
    for word in words {
        stream.write_u32(*word).await?;
    }
    stream.flush().await
}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if !(4..=MAX_PACKET).contains(&length) {
        return Err(invalid_packet());
    }
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet).await?;
    Ok(packet)
}

fn take_word(packet: &mut &[u8]) -> io::Result<u32> {
    let bytes = packet.get(..4).ok_or_else(invalid_packet)?;
    let word = u32::from_be_bytes(bytes.try_into().map_err(|_| invalid_packet())?);
    *packet = &packet[4..];
    Ok(word)
}

fn take_string(packet: &mut &[u8]) -> io::Result<()> {
    let length = take_word(packet)? as usize;
    *packet = packet.get(length..).ok_or_else(invalid_packet)?;
    Ok(())
}

fn check_hello(mut packet: &[u8]) -> io::Result<()> {
    if take_word(&mut packet)? != MUX_HELLO || take_word(&mut packet)? != 4 {
        return Err(invalid_packet());
    }
    // OpenSSH may advertise extensions, including the newer "info" one.
    // Ignore unknown names but require complete, bounded name/value pairs.
    while !packet.is_empty() {
        take_string(&mut packet)?;
        take_string(&mut packet)?;
    }
    Ok(())
}

async fn check_master<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    pid: u32,
) -> io::Result<()> {
    write_packet(stream, &[MUX_HELLO, 4]).await?;
    check_hello(&read_packet(stream).await?)?;
    write_packet(stream, &[MUX_ALIVE_CHECK, ALIVE_REQUEST]).await?;
    let packet = read_packet(stream).await?;
    let mut reply = packet.as_slice();
    if take_word(&mut reply)? != MUX_ALIVE
        || take_word(&mut reply)? != ALIVE_REQUEST
        || take_word(&mut reply)? != pid
        || !reply.is_empty()
    {
        return Err(invalid_packet());
    }
    Ok(())
}

async fn stop_listening<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    write_packet(stream, &[MUX_STOP_LISTENING, STOP_REQUEST]).await?;
    let packet = read_packet(stream).await?;
    let mut reply = packet.as_slice();
    if take_word(&mut reply)? != MUX_OK
        || take_word(&mut reply)? != STOP_REQUEST
        || !reply.is_empty()
    {
        return Err(invalid_packet());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    #[test]
    fn hello_accepts_extensions_but_refuses_bad_framing() {
        let hello = words(&[MUX_HELLO, 4]);
        assert!(check_hello(&hello).is_ok());
        let mut extension = hello.clone();
        extension.extend(words(&[4]));
        extension.extend(b"info");
        extension.extend(words(&[1]));
        extension.extend(b"0");
        assert!(check_hello(&extension).is_ok());
        for end in hello.len() + 1..extension.len() {
            assert!(
                check_hello(&extension[..end]).is_err(),
                "truncation at {end}"
            );
        }
        assert!(check_hello(&words(&[MUX_HELLO, 5])).is_err());
        assert!(check_hello(&words(&[MUX_OK, 4])).is_err());
        assert!(check_hello(&words(&[MUX_HELLO, 4, u32::MAX])).is_err());
    }

    #[test]
    fn only_generated_rch_child_names_are_candidates() {
        for name in ["rch-abc123", "rch-ZYX987654321"] {
            assert!(managed_directory_name(OsStr::new(name)));
        }
        for name in [
            "rch-",
            "rch-a",
            "other-abc123",
            "../rch-abc123",
            "rch-abc123/master",
            "rch-abc 123",
        ] {
            assert!(!managed_directory_name(OsStr::new(name)));
        }
    }

    #[test]
    fn directory_anchors_reject_symlinks_permissions_and_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rch");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = Directory::open(&path).unwrap();
        root.revalidate().unwrap();

        let link = temp.path().join("linked-rch");
        symlink(&path, &link).unwrap();
        assert!(Directory::open(&link).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Directory::open(&path).is_err());
        assert!(root.revalidate().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        std::fs::rename(&path, temp.path().join("retained-rch")).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(root.revalidate().is_err());
    }

    #[test]
    fn candidate_refuses_non_socket_and_symlinked_children_without_removing_them() {
        let temp = tempfile::tempdir().unwrap();
        let root = Directory::open(temp.path()).unwrap();
        let name = OsString::from("rch-abc123");
        let child = temp.path().join(&name);
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("master"), "not a socket").unwrap();
        assert!(Candidate::open(&root, name).is_err());
        assert_eq!(
            std::fs::read_to_string(child.join("master")).unwrap(),
            "not a socket"
        );
        symlink(&child, temp.path().join("rch-def456")).unwrap();
        assert!(Candidate::open(&root, OsString::from("rch-def456")).is_err());
        assert!(temp.path().join("rch-def456").is_symlink());
    }

    #[tokio::test]
    async fn mux_drains_on_same_stream_after_matching_alive() {
        let (mut client, mut server) = tokio::io::duplex(MAX_PACKET);
        let server_task = tokio::spawn(async move {
            assert_eq!(
                read_packet(&mut server).await.unwrap(),
                words(&[MUX_HELLO, 4])
            );
            write_packet(&mut server, &[MUX_HELLO, 4]).await.unwrap();
            assert_eq!(
                read_packet(&mut server).await.unwrap(),
                words(&[MUX_ALIVE_CHECK, ALIVE_REQUEST])
            );
            write_packet(&mut server, &[MUX_ALIVE, ALIVE_REQUEST, 1234])
                .await
                .unwrap();
            assert_eq!(
                read_packet(&mut server).await.unwrap(),
                words(&[MUX_STOP_LISTENING, STOP_REQUEST])
            );
            write_packet(&mut server, &[MUX_OK, STOP_REQUEST])
                .await
                .unwrap();
        });
        check_master(&mut client, 1234).await.unwrap();
        stop_listening(&mut client).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn mux_refuses_mismatched_pid_id_type_or_trailing_data_before_stop() {
        for response in [
            vec![MUX_ALIVE, ALIVE_REQUEST, 5678],
            vec![MUX_ALIVE, STOP_REQUEST, 1234],
            vec![MUX_OK, ALIVE_REQUEST, 1234],
            vec![MUX_ALIVE, ALIVE_REQUEST, 1234, 0],
            vec![MUX_ALIVE, ALIVE_REQUEST],
        ] {
            let (mut client, mut server) = tokio::io::duplex(MAX_PACKET);
            let server_task = tokio::spawn(async move {
                read_packet(&mut server).await.unwrap();
                write_packet(&mut server, &[MUX_HELLO, 4]).await.unwrap();
                read_packet(&mut server).await.unwrap();
                write_packet(&mut server, &response).await.unwrap();
                // Refusal must close the probe without sending any STOP.
                let mut byte = [0];
                assert_eq!(server.read(&mut byte).await.unwrap(), 0);
            });
            assert!(check_master(&mut client, 1234).await.is_err());
            drop(client);
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn mux_bounds_packet_allocation() {
        for length in [0, 3, MAX_PACKET as u32 + 1, u32::MAX] {
            let (mut client, mut server) = tokio::io::duplex(16);
            server.write_u32(length).await.unwrap();
            assert_eq!(
                read_packet(&mut client).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unresponsive_mux_expires_without_stop() {
        let (mut client, mut server) = tokio::io::duplex(MAX_PACKET);
        let probe = tokio::spawn(async move {
            let deadline = Instant::now() + CANDIDATE_TIMEOUT;
            timeout_at(deadline, check_master(&mut client, 1234)).await
        });
        assert_eq!(
            read_packet(&mut server).await.unwrap(),
            words(&[MUX_HELLO, 4])
        );
        tokio::time::advance(CANDIDATE_TIMEOUT).await;
        assert!(probe.await.unwrap().is_err());
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    }
}
