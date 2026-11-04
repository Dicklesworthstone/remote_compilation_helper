//! Native bounded I/O for the canonical service's pure framing contract.

use rabs_protocol::canonical_service::{HEADER_BYTES, Header, Kind};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) const POLL: Duration = Duration::from_millis(100);

/// No blocking connect may outlive the caller's deadline, even when the
/// listener's backlog is full. Credentials are checked on the connected FD.
pub(super) fn connect(
    path: &Path,
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<UnixStream> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let address = SocketAddrUnix::new(path)?;
    loop {
        checkpoint(deadline, stopped)?;
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) => {}
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                // Linux AF_UNIX reports EAGAIN when its listen queue is full;
                // unlike EINPROGRESS, that socket has no pending connection.
                std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
                continue;
            }
            Err(rustix::io::Errno::INPROGRESS) => loop {
                checkpoint(deadline, stopped)?;
                let duration = POLL.min(deadline.saturating_duration_since(Instant::now()));
                let timeout = Timespec {
                    tv_sec: 0,
                    tv_nsec: duration.subsec_nanos().into(),
                };
                let mut descriptors = [PollFd::new(&socket, PollFlags::OUT)];
                match poll(&mut descriptors, Some(&timeout)) {
                    Ok(0) | Err(rustix::io::Errno::INTR) => continue,
                    Ok(_) => {
                        rustix::net::sockopt::socket_error(&socket)??;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            },
            Err(error) => return Err(error.into()),
        }
        let stream = UnixStream::from(socket);
        stream.set_nonblocking(false)?;
        configure(&stream)?;
        require_owner(&stream)?;
        return Ok(stream);
    }
}

pub(super) fn require_owner(stream: &UnixStream) -> io::Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)?;
    if credentials.uid != rustix::process::geteuid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "canonical service peer is owned by a different user",
        ));
    }
    Ok(())
}

pub(super) fn configure(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(POLL))?;
    stream.set_write_timeout(Some(POLL))
}

fn checkpoint(deadline: Instant, stopped: &AtomicBool) -> io::Result<()> {
    if stopped.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "canonical service request cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "canonical service I/O deadline elapsed",
        ));
    }
    Ok(())
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn read_exact(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        checkpoint(deadline, stopped)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "canonical service frame was truncated",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        checkpoint(deadline, stopped)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "canonical service output stopped",
                ));
            }
            Ok(count) => offset += count,
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn receive(
    stream: &mut UnixStream,
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<(Header, Vec<u8>)> {
    let mut header = [0; HEADER_BYTES];
    read_exact(stream, &mut header, deadline, stopped)?;
    let header = Header::decode(header).map_err(io::Error::other)?;
    let mut bytes = vec![0; header.length()];
    read_exact(stream, &mut bytes, deadline, stopped)?;
    header.validate_payload(&bytes).map_err(io::Error::other)?;
    Ok((header, bytes))
}

pub(super) fn send(
    stream: &mut UnixStream,
    kind: Kind,
    bytes: &[u8],
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let header = Header::new(kind, bytes.len()).map_err(io::Error::other)?;
    header.validate_payload(bytes).map_err(io::Error::other)?;
    write_all(stream, &header.encode(), deadline, stopped)?;
    write_all(stream, bytes, deadline, stopped)
}

/// An overloaded service can refuse before reading the request. Preserve its
/// bounded terminal explanation if closing that socket races our first write.
/// No other frame can excuse an incomplete request, and there is no retry.
pub(super) fn submit(
    stream: &mut UnixStream,
    profile: &[u8],
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<Option<(Header, Vec<u8>)>> {
    // Invalid local profiles must fail without reading a peer's response.
    Header::new(Kind::Profile, profile.len()).map_err(io::Error::other)?;
    match send(stream, Kind::Profile, profile, deadline, stopped) {
        Ok(()) => Ok(None),
        Err(error) => match receive(stream, deadline, stopped) {
            Ok((header, payload)) if header.kind() == Kind::Failed => Ok(Some((header, payload))),
            _ => Err(error),
        },
    }
}

pub(super) fn expect_eof(
    stream: &mut UnixStream,
    deadline: Instant,
    stopped: &AtomicBool,
) -> io::Result<()> {
    let mut byte = [0];
    loop {
        checkpoint(deadline, stopped)?;
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "canonical service sent data after its terminal result",
                ));
            }
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::canonical_service::{MAX_CHUNK_BYTES, ResponseState};
    use std::sync::Arc;

    #[test]
    fn native_connect_checks_peer_and_bounds_a_full_listener_backlog() {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("service.sock");
        let listener = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        rustix::net::bind(&listener, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        // Linux admits one queued connection with backlog zero. Keeping that
        // connection unaccepted exercises AF_UNIX's real EAGAIN behavior.
        rustix::net::listen(&listener, 0).unwrap();
        let stopped = AtomicBool::new(false);
        let _queued = connect(&path, Instant::now() + Duration::from_secs(5), &stopped).unwrap();
        let error =
            connect(&path, Instant::now() + Duration::from_millis(200), &stopped).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        stopped.store(true, Ordering::Release);
        assert_eq!(
            connect(&path, Instant::now() + Duration::from_secs(5), &stopped)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn refusal_before_request_write_preserves_busy_reason_without_resubmission() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        configure(&client).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let stopped = AtomicBool::new(false);
        send(
            &mut server,
            Kind::Failed,
            b"service is busy",
            deadline,
            &stopped,
        )
        .unwrap();
        drop(server);
        let (header, payload) = submit(&mut client, b"{}", deadline, &stopped)
            .unwrap()
            .expect("closed peer makes request write fail");
        assert_eq!(header.kind(), Kind::Failed);
        assert_eq!(payload, b"service is busy");
        expect_eof(&mut client, deadline, &stopped).unwrap();

        let (mut client, mut server) = UnixStream::pair().unwrap();
        configure(&client).unwrap();
        send(&mut server, Kind::Accepted, &[], deadline, &stopped).unwrap();
        drop(server);
        assert!(submit(&mut client, b"{}", deadline, &stopped).is_err());
    }

    #[test]
    fn native_socket_preserves_fragmented_binary_chunks_and_terminal_status() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        configure(&client).unwrap();
        configure(&server).unwrap();
        let bytes = [0, 255, b'\n', b'\r', b'{', b'}'];
        let writer = std::thread::spawn(move || {
            let stopped = AtomicBool::new(false);
            let deadline = Instant::now() + Duration::from_secs(5);
            send(&mut server, Kind::Accepted, &[], deadline, &stopped).unwrap();
            let header = Header::new(Kind::Stdout, bytes.len()).unwrap().encode();
            for byte in header.into_iter().chain(bytes) {
                server.write_all(&[byte]).unwrap();
            }
            send(
                &mut server,
                Kind::Completed,
                &101_i32.to_be_bytes(),
                deadline,
                &stopped,
            )
            .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let stopped = AtomicBool::new(false);
        let mut state = ResponseState::default();
        for expected in [Kind::Accepted, Kind::Stdout, Kind::Completed] {
            let (header, payload) = receive(&mut client, deadline, &stopped).unwrap();
            assert_eq!(header.kind(), expected);
            if expected == Kind::Stdout {
                assert_eq!(payload, bytes);
            }
            state.observe(header, &payload).unwrap();
        }
        expect_eof(&mut client, deadline, &stopped).unwrap();
        state.finish().unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn oversized_header_and_truncation_fail_without_waiting_for_claimed_body() {
        for bytes in [
            vec![1, Kind::Stdout as u8, 255, 255, 255, 255],
            vec![1, 3, 0, 0, 0, 4, 1],
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            configure(&client).unwrap();
            server.write_all(&bytes).unwrap();
            drop(server);
            assert!(
                receive(
                    &mut client,
                    Instant::now() + Duration::from_secs(1),
                    &AtomicBool::new(false)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn cancellation_interrupts_a_silent_peer_and_one_connection_does_not_cancel_another() {
        let (mut first, _silent) = UnixStream::pair().unwrap();
        let (mut other, mut peer) = UnixStream::pair().unwrap();
        configure(&first).unwrap();
        configure(&other).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&stopped);
        let reader = std::thread::spawn(move || {
            receive(
                &mut first,
                Instant::now() + Duration::from_secs(5),
                &observed,
            )
        });
        stopped.store(true, Ordering::Release);
        assert_eq!(
            reader.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        send(
            &mut peer,
            Kind::Accepted,
            &[],
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            receive(
                &mut other,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false)
            )
            .unwrap()
            .0
            .kind(),
            Kind::Accepted
        );
    }

    #[test]
    fn slow_output_reader_and_extra_terminal_bytes_are_bounded() {
        let (mut writer, _not_reading) = UnixStream::pair().unwrap();
        configure(&writer).unwrap();
        let deadline = Instant::now() + Duration::from_millis(200);
        let bytes = vec![8; MAX_CHUNK_BYTES];
        let error = loop {
            if let Err(error) = send(
                &mut writer,
                Kind::Stdout,
                &bytes,
                deadline,
                &AtomicBool::new(false),
            ) {
                break error;
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let (mut reader, mut peer) = UnixStream::pair().unwrap();
        configure(&reader).unwrap();
        peer.write_all(b"extra").unwrap();
        assert_eq!(
            expect_eof(
                &mut reader,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
