//! Caller-owned output without an uncancellable pipe or socket write.
//!
//! Reopening a pipe/terminal through our retained descriptor gives this writer
//! its own nonblocking file description. The shell's descriptor flags stay
//! untouched. Regular files keep their original shared offset and append mode;
//! socket writes use per-call nonblocking flags. No forwarding thread can be
//! stranded behind a consumer that stopped reading.

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{FileType, Mode, OFlags, fcntl_getfl, fstat, open};
use rustix::io::{Errno, fcntl_dupfd_cloexec};
use rustix::net::{SendFlags, send};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const OUTPUT_POLL: Duration = Duration::from_millis(50);
const WRITE_BYTES: usize = 64 * 1024;

/// Every retained caller sink observes the same monotonically shortened bound.
/// A completed build's delivery budget must replace its longer execution budget
/// even when a write is already waiting for a pipe or socket to become writable.
#[derive(Clone)]
pub(super) struct OutputDeadline(Arc<Mutex<Instant>>);

impl OutputDeadline {
    pub(super) fn new(deadline: Instant) -> Self {
        Self(Arc::new(Mutex::new(deadline)))
    }

    pub(super) fn get(&self) -> Instant {
        *self.0.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(super) fn limit(&self, deadline: Instant) {
        let mut current = self.0.lock().unwrap_or_else(|error| error.into_inner());
        *current = (*current).min(deadline);
    }
}

pub(super) struct ControlledOutput<'a> {
    descriptor: OwnedFd,
    socket: bool,
    stopped: &'a AtomicBool,
    deadline: OutputDeadline,
}

impl<'a> ControlledOutput<'a> {
    pub(super) fn new(
        output: &impl AsFd,
        stopped: &'a AtomicBool,
        deadline: Instant,
    ) -> io::Result<Self> {
        Self::with_deadline(output, stopped, OutputDeadline::new(deadline))
    }

    pub(super) fn with_deadline(
        output: &impl AsFd,
        stopped: &'a AtomicBool,
        deadline: OutputDeadline,
    ) -> io::Result<Self> {
        // Keep the exact original description alive while inspecting/reopening
        // it; a concurrent close/reuse of stdout's number cannot redirect us.
        let retained = fcntl_dupfd_cloexec(output, 0)?;
        let before = fstat(&retained)?;
        let kind = FileType::from_raw_mode(before.st_mode);
        let flags = fcntl_getfl(&retained)?;
        if !flags.intersects(OFlags::WRONLY | OFlags::RDWR) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "remote output descriptor is not writable",
            ));
        }
        let descriptor = match kind {
            FileType::Fifo | FileType::CharacterDevice => {
                if kind == FileType::CharacterDevice {
                    // Reopening a PTY master clones /dev/ptmx. Both masters
                    // have the same stat identity but different terminal
                    // peers, so the checks below cannot detect lost output.
                    match rustix::pty::ptsname(&retained, Vec::new()) {
                        Ok(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "remote output cannot reopen a pseudoterminal master",
                            ));
                        }
                        Err(Errno::NOTTY) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let descriptor = open(
                    format!("/proc/self/fd/{}", retained.as_raw_fd()),
                    OFlags::WRONLY
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC
                        | OFlags::NOCTTY
                        | (flags & (OFlags::APPEND | OFlags::DIRECT)),
                    Mode::empty(),
                )?;
                let after = fstat(&descriptor)?;
                if before.st_dev != after.st_dev
                    || before.st_ino != after.st_ino
                    || before.st_rdev != after.st_rdev
                    || FileType::from_raw_mode(after.st_mode) != kind
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "remote output descriptor changed while opening its controlled writer",
                    ));
                }
                descriptor
            }
            FileType::RegularFile | FileType::Socket => retained,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "remote output requires a regular file, pipe, terminal or socket",
                ));
            }
        };
        Ok(Self {
            descriptor,
            socket: kind == FileType::Socket,
            stopped,
            deadline,
        })
    }

    fn checkpoint(&self) -> io::Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "remote diagnostic delivery cancelled",
            ))
        } else if Instant::now() >= self.deadline.get() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "remote diagnostic delivery deadline exceeded",
            ))
        } else {
            Ok(())
        }
    }

    fn wait_writable(&self) -> io::Result<()> {
        self.checkpoint()?;
        let remaining = self
            .deadline
            .get()
            .saturating_duration_since(Instant::now());
        // The poll interval is bounded below one second, so this conversion
        // cannot overflow the kernel's signed seconds representation.
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(remaining.min(OUTPUT_POLL).subsec_nanos()),
        };
        let mut descriptors = [PollFd::new(&self.descriptor, PollFlags::OUT)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {
                self.checkpoint()?;
                // Let write/send report HUP/ERR precisely. An invalid retained
                // descriptor must not become an immediate polling spin.
                if descriptors[0].revents().contains(PollFlags::NVAL) {
                    return Err(io::Error::from(Errno::BADF));
                }
                Ok(())
            }
            Err(Errno::INTR) => self.checkpoint(),
            Err(error) => Err(error.into()),
        }
    }
}

impl Write for ControlledOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.checkpoint()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let bytes = &bytes[..bytes.len().min(WRITE_BYTES)];
        loop {
            self.checkpoint()?;
            let result = if self.socket {
                send(
                    &self.descriptor,
                    bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                )
            } else {
                rustix::io::write(&self.descriptor, bytes)
            };
            match result {
                Ok(written) => return Ok(written),
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => self.wait_writable()?,
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        // Write's default retries Interrupted forever. Here it also means an
        // explicit cancellation, so retry only the syscall EINTR handled above.
        self.checkpoint()?;
        while !bytes.is_empty() {
            let written = self.write(bytes)?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[written..];
        }
        self.checkpoint()
    }

    fn flush(&mut self) -> io::Result<()> {
        // Every byte goes directly to the retained descriptor; no buffer or
        // fsync transaction is introduced for transcript presentation.
        self.checkpoint()
    }
}

/// Exercise a production stderr writer in an isolated instance of the current
/// test harness. The inherited blocking pipe is genuinely full (EAGAIN), while
/// stdout retains the test verdict. A regression cannot strand the test runner
/// or leave its child running. Pass the test's complete `module_path!()` name.
#[cfg(test)]
pub(crate) fn with_stalled_stderr(test_name: &str, case: impl FnOnce()) {
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::process::{Child, Command, Stdio};

    const CHILD_TEST: &str = "RABS_STALLED_STDERR_TEST";
    const CHILD_ROOT: &str = "RABS_STALLED_STDERR_TEST_ROOT";
    const COMPLETED: &str = "RABS_STALLED_STDERR_CASE_COMPLETED";
    let test_name = test_name.strip_prefix("rabsd::").unwrap_or(test_name);
    if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
        let root = std::path::PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
        fs::write(root.join("ready"), b"native test body ready").unwrap();
        std::io::stdin().read_exact(&mut [0_u8]).unwrap();
        case();
        println!("{COMPLETED}");
        return;
    }

    struct ChildOwner(Child);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    let root = crate::test_util::private_tempdir();
    let (_reader, writer) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC,
    )
    .unwrap();
    let bytes = [0x5a; 4096];
    loop {
        match rustix::io::write(&writer, &bytes) {
            Ok(count) => assert!(count > 0),
            Err(rustix::io::Errno::AGAIN) => break,
            result => panic!("unexpected stderr-pipe fill: {result:?}"),
        }
    }
    assert_eq!(
        rustix::io::write(&writer, b"x"),
        Err(rustix::io::Errno::AGAIN)
    );
    let flags = rustix::fs::fcntl_getfl(&writer).unwrap() & !rustix::fs::OFlags::NONBLOCK;
    rustix::fs::fcntl_setfl(&writer, flags).unwrap();
    let writer = File::from(writer);
    let log_path = root.path().join("child.log");
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_TEST, test_name)
            .env(CHILD_ROOT, root.path())
            .stdin(Stdio::piped())
            .stdout(File::create(&log_path).unwrap())
            .stderr(writer.try_clone().unwrap())
            .spawn()
            .unwrap(),
    );
    // Loader/startup latency is separate from the bounded production operation.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "stderr regression child did not enter {test_name}: {}",
            fs::read_to_string(&log_path).unwrap(),
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.stdin.take().unwrap().write_all(b"x").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "{test_name} retained ownership behind stalled stderr: {}",
            fs::read_to_string(&log_path).unwrap(),
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let log = fs::read_to_string(log_path).unwrap();
    assert!(status.success(), "{test_name} child failed: {log}");
    assert!(
        log.contains(COMPLETED),
        "{test_name} body did not finish: {log}"
    );
    assert_eq!(rustix::fs::fcntl_getfl(&writer).unwrap(), flags);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::{Arc, mpsc};

    fn fill_pipe(writer: &impl AsFd) -> usize {
        let bytes = [0x5a; 4096];
        let mut total = 0;
        loop {
            match rustix::io::write(writer, &bytes) {
                Ok(count) => total += count,
                Err(Errno::AGAIN) => return total,
                result => panic!("unexpected pipe fill result: {result:?}"),
            }
        }
    }

    #[test]
    fn blocked_pipe_write_all_observes_cancellation_without_changing_caller_flags() {
        let (_reader, writer) = rustix::pipe::pipe().unwrap();
        let flags = fcntl_getfl(&writer).unwrap();
        let stopped = AtomicBool::new(false);
        let mut output =
            ControlledOutput::new(&writer, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        assert!(fill_pipe(&output.descriptor) > 0);
        assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
        std::thread::scope(|scope| {
            let (sender, receiver) = mpsc::channel();
            scope.spawn(move || {
                sender.send(output.write_all(b"must wait")).unwrap();
            });
            // A full real pipe must hold the writer until cancellation arrives.
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(75)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            stopped.store(true, Ordering::Release);
            assert_eq!(
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("cancellation must unblock the real output writer")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Interrupted
            );
        });
        assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
    }

    #[test]
    fn blocked_pipe_deadline_is_fixed_and_does_not_spin_on_interrupted_write_all() {
        let (_reader, writer) = rustix::pipe::pipe().unwrap();
        let stopped = AtomicBool::new(false);
        let mut output = ControlledOutput::new(
            &writer,
            &stopped,
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
        assert!(fill_pipe(&output.descriptor) > 0);
        let start = Instant::now();
        assert_eq!(
            output.write_all(b"no reader").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn blocked_pipe_observes_shortened_shared_delivery_deadline() {
        let (_reader, writer) = rustix::pipe::pipe().unwrap();
        let stopped = AtomicBool::new(false);
        let operation_deadline = Instant::now() + Duration::from_secs(5);
        let deadline = OutputDeadline::new(operation_deadline);
        let mut output =
            ControlledOutput::with_deadline(&writer, &stopped, deadline.clone()).unwrap();
        assert!(fill_pipe(&output.descriptor) > 0);
        std::thread::scope(|scope| {
            let (sender, receiver) = mpsc::channel();
            scope.spawn(move || {
                sender.send(output.write_all(b"verified stdout")).unwrap();
            });
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(75)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            let delivery_deadline = Instant::now() + Duration::from_millis(50);
            deadline.limit(delivery_deadline);
            // Repeated completion/reconnect bookkeeping cannot renew the
            // already shortened deadline of a currently blocked caller sink.
            deadline.limit(operation_deadline);
            assert_eq!(deadline.get(), delivery_deadline);
            assert_eq!(
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("shortened delivery budget must interrupt the real output writer")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
        });
        assert!(!stopped.load(Ordering::Acquire));
    }

    #[test]
    fn slow_pipe_receives_exact_binary_bytes_without_a_forwarding_thread() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let stopped = AtomicBool::new(false);
        let mut output =
            ControlledOutput::new(&writer, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        let bytes: Vec<_> = (0..256).cycle().take(256 * 1024).map(|n| n as u8).collect();
        let expected = bytes.clone();
        std::thread::scope(|scope| {
            let receiver = scope.spawn(move || {
                let mut reader = File::from(reader);
                let mut received = vec![0; expected.len()];
                for chunk in received.chunks_mut(2048) {
                    reader.read_exact(chunk).unwrap();
                }
                assert_eq!(received, expected);
            });
            output.write_all(&bytes).unwrap();
            output.flush().unwrap();
            receiver.join().unwrap();
        });
    }

    #[test]
    fn regular_file_output_preserves_shared_offset_and_append_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("output");
        let stopped = AtomicBool::new(false);
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(b"prior-").unwrap();
        let mut output =
            ControlledOutput::new(&file, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        output.write_all(b"current").unwrap();
        assert_eq!(file.stream_position().unwrap(), 13);
        assert_eq!(fs::read(&path).unwrap(), b"prior-current");
        let mut append = OpenOptions::new().append(true).open(&path).unwrap();
        append.seek(SeekFrom::Start(0)).unwrap();
        let mut output =
            ControlledOutput::new(&append, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        output.write_all(b"-tail").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"prior-current-tail");
    }

    #[test]
    fn closed_reader_and_read_only_outputs_are_errors_not_successful_exposure() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let stopped = AtomicBool::new(false);
        let mut output =
            ControlledOutput::new(&writer, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        drop(reader);
        assert_eq!(
            output.write_all(b"lost consumer").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let file = File::open("/dev/null").unwrap();
        assert_eq!(
            ControlledOutput::new(&file, &stopped, Instant::now() + Duration::from_secs(5))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let sink = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let flags = fcntl_getfl(&sink).unwrap();
        let mut output =
            ControlledOutput::new(&sink, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        output
            .write_all(b"discarded by the caller's chosen sink")
            .unwrap();
        assert_eq!(fcntl_getfl(&sink).unwrap(), flags);
    }

    #[test]
    fn socket_output_cancels_without_modifying_shared_nonblocking_flags() {
        let (writer, _reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let flags = fcntl_getfl(&writer).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stopped);
        let worker = std::thread::spawn(move || {
            let mut output = ControlledOutput::new(
                &writer,
                &worker_stop,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            let buffer = [0; WRITE_BYTES];
            loop {
                match send(&writer, &buffer, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
                    Ok(_) => {}
                    Err(Errno::AGAIN) => break,
                    result => panic!("unexpected socket fill result: {result:?}"),
                }
            }
            assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
            let result = output.write_all(b"blocked");
            assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
            result
        });
        std::thread::sleep(Duration::from_millis(100));
        stopped.store(true, Ordering::Release);
        assert_eq!(
            worker.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn blocked_terminal_cancels_without_changing_inherited_descriptor_flags() {
        use rustix::pty::{OpenptFlags, ioctl_tiocgptpeer, openpt, unlockpt};

        let open_flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let terminal = openpt(open_flags).unwrap();
        unlockpt(&terminal).unwrap();
        let writer = ioctl_tiocgptpeer(&terminal, open_flags).unwrap();
        let flags = fcntl_getfl(&writer).unwrap();
        assert!(!flags.contains(OFlags::NONBLOCK));
        let stopped = AtomicBool::new(false);
        let mut output =
            ControlledOutput::new(&writer, &stopped, Instant::now() + Duration::from_secs(5))
                .unwrap();
        assert!(
            fcntl_getfl(&output.descriptor)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );
        // Fill the real terminal output queue while its master does not read.
        // Bound setup too: an unexpectedly unbounded device must fail the test.
        let bytes = [b'x'; 4096];
        let mut total = 0;
        loop {
            match rustix::io::write(&output.descriptor, &bytes) {
                Ok(count) => {
                    assert!(count > 0);
                    total += count;
                    assert!(total < 1024 * 1024, "terminal never applied backpressure");
                }
                Err(Errno::AGAIN) => break,
                result => panic!("unexpected terminal fill result: {result:?}"),
            }
        }
        assert!(total > 0);
        assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
        std::thread::scope(|scope| {
            let (sender, receiver) = mpsc::channel();
            scope.spawn(move || {
                // The driver may still move a final small buffer into the
                // master's queue after EAGAIN. This exceeds both queues.
                sender.send(output.write_all(&[b'y'; 256 * 1024])).unwrap();
            });
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(75)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            stopped.store(true, Ordering::Release);
            assert_eq!(
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("cancellation must unblock the terminal writer")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Interrupted
            );
        });
        assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
    }

    #[test]
    fn terminal_master_is_refused_even_when_reopen_has_the_same_stat_identity() {
        use rustix::pty::{OpenptFlags, openpt, ptsname};

        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = openpt(flags).unwrap();
        let original_flags = fcntl_getfl(&master).unwrap();
        // Reproduce the alias that ordinary inode checks miss: Linux reports
        // the same clone-device identity for two unrelated terminal masters.
        let reopened = open(
            format!("/proc/self/fd/{}", master.as_raw_fd()),
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )
        .unwrap();
        let before = fstat(&master).unwrap();
        let after = fstat(&reopened).unwrap();
        assert_eq!(
            (before.st_dev, before.st_ino, before.st_rdev),
            (after.st_dev, after.st_ino, after.st_rdev)
        );
        assert_ne!(
            ptsname(&master, Vec::new()).unwrap(),
            ptsname(&reopened, Vec::new()).unwrap()
        );
        let stopped = AtomicBool::new(false);
        assert_eq!(
            ControlledOutput::new(&master, &stopped, Instant::now() + Duration::from_secs(5))
                .err()
                .expect("cloning a master must not acknowledge output to another terminal")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(fcntl_getfl(&master).unwrap(), original_flags);
    }
}
