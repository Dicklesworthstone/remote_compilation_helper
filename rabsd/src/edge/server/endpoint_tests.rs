use super::*;
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixDatagram, UnixListener as StdListener, UnixStream as StdStream};

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    block_on_top_level(&runtime, future)
}

fn identity(path: &Path) -> (u64, u64, i64, i64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec())
}

#[cfg(target_os = "linux")]
#[test]
fn blocked_stderr_retirement_child() {
    use std::io::Read;

    let Some(root) = std::env::var_os("RABS_EDGE_LOG_LOCK_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    // Even before binding, this production owner fences every other daemon
    // from taking the endpoint. Its Drop must release the actual native lock.
    let owner = EndpointOwner(EndpointLease::acquire(&root.join("edge.sock")).unwrap());
    fs::write(root.join("ready"), b"endpoint lease held").unwrap();
    std::io::stdin().read_exact(&mut [0_u8]).unwrap();
    drop(owner);
    fs::write(root.join("retired"), b"endpoint owner dropped").unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn blocked_stderr_cannot_strand_the_native_endpoint_lease() {
    use std::io::Write;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

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
    let path = root.path().join("edge.sock");
    let (_reader, writer) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::NONBLOCK | rustix::pipe::PipeFlags::CLOEXEC,
    )
    .unwrap();
    let bytes = [0x5a; 4096];
    loop {
        match rustix::io::write(&writer, &bytes) {
            Ok(count) => assert!(count > 0),
            Err(rustix::io::Errno::AGAIN) => break,
            result => panic!("unexpected caller-pipe fill: {result:?}"),
        }
    }
    let flags = rustix::fs::fcntl_getfl(&writer).unwrap() & !rustix::fs::OFlags::NONBLOCK;
    rustix::fs::fcntl_setfl(&writer, flags).unwrap();
    let writer = fs::File::from(writer);
    let log = fs::File::create(root.path().join("child.log")).unwrap();
    // Exercise actual production Drop with an inherited full stderr, not a
    // substituted retirement function or a process-global fd redirection.
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "edge::server::endpoint::tests::blocked_stderr_retirement_child",
                "--nocapture",
            ])
            .env("RABS_EDGE_LOG_LOCK_TEST_ROOT", root.path())
            .stdin(Stdio::piped())
            .stdout(log)
            .stderr(writer.try_clone().unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "endpoint child did not acquire its lease: {}",
            fs::read_to_string(root.path().join("child.log")).unwrap(),
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(EndpointLease::acquire(&path).is_err());
    child.0.stdin.take().unwrap().write_all(b"retire").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the endpoint owner stranded its lease behind a blocked stderr",
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "endpoint child failed: {}",
        fs::read_to_string(root.path().join("child.log")).unwrap(),
    );
    assert_eq!(
        fs::read(root.path().join("retired")).unwrap(),
        b"endpoint owner dropped",
    );
    EndpointLease::acquire(&path).unwrap();
    assert_eq!(rustix::fs::fcntl_getfl(&writer).unwrap(), flags);
}

#[test]
fn bound_listener_is_private_and_retirement_is_generation_owned() {
    let root = crate::test_util::private_tempdir();
    let path = root.path().join("new-parent/edge.sock");
    let listener = run(bind_inner(&path, Duration::from_secs(1))).unwrap();
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(listener.owner_uid(), fs::metadata(&path).unwrap().uid());
    assert!(StdStream::connect(&path).is_ok());
    assert!(run(bind_inner(&path, Duration::from_secs(1))).is_err());
    drop(listener);
    assert!(fs::symlink_metadata(&path).is_err());
    let successor = run(bind_inner(&path, Duration::from_secs(1))).unwrap();
    drop(successor);
    assert!(
        path.parent()
            .unwrap()
            .join(".rabs-edge.sock.endpoint.lock")
            .is_file()
    );
}

#[test]
fn admitted_connection_owner_fences_restart_after_listener_drop() {
    let root = crate::test_util::private_tempdir();
    let path = root.path().join("edge.sock");
    let listener = run(bind_inner(&path, Duration::from_secs(1))).unwrap();
    let peer = StdStream::connect(&path).unwrap();
    let (session, _) = run(listener.listener.accept()).unwrap();
    // Exactly the owner cloned into each real handle_connection task.
    let session_owner = Arc::clone(&listener.owner);
    drop(listener);
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    assert!(run(bind_inner(&path, Duration::from_secs(1))).is_err());
    drop(session);
    drop(peer);
    // Session-side joined work may outlive the socket itself.
    assert!(run(bind_inner(&path, Duration::from_secs(1))).is_err());
    drop(session_owner);
    assert!(fs::symlink_metadata(&path).is_err());
    assert!(run(bind_inner(&path, Duration::from_secs(1))).is_ok());
}

#[test]
fn actual_dead_socket_is_recovered_but_live_legacy_listener_is_not() {
    let root = crate::test_util::private_tempdir();
    let path = root.path().join("edge.sock");
    let legacy = StdListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = identity(&path);
    assert!(run(bind_inner(&path, Duration::from_secs(1))).is_err());
    assert_eq!(identity(&path), before);
    assert!(StdStream::connect(&path).is_ok());
    drop(legacy);
    let successor = run(bind_inner(&path, Duration::from_secs(1))).unwrap();
    assert!(StdStream::connect(&path).is_ok());
    drop(successor);
}

#[test]
fn actual_wrong_socket_protocol_error_is_not_proof_of_death() {
    let root = crate::test_util::private_tempdir();
    let path = root.path().join("datagram.sock");
    let datagram = UnixDatagram::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = identity(&path);
    let error = StdStream::connect(&path).unwrap_err();
    assert_ne!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(run(bind_inner(&path, Duration::from_secs(1))).is_err());
    assert_eq!(identity(&path), before);
    let peer = UnixDatagram::unbound().unwrap();
    assert_eq!(peer.send_to(b"still live", &path).unwrap(), 10);
    let mut buffer = [0; 10];
    assert_eq!(datagram.recv(&mut buffer).unwrap(), 10);
    assert_eq!(&buffer, b"still live");
}

#[test]
fn regular_and_symlink_entries_survive_failed_startup() {
    let root = crate::test_util::private_tempdir();
    let file = root.path().join("important");
    fs::write(&file, b"never daemon state").unwrap();
    let before = identity(&file);
    assert!(run(bind_inner(&file, Duration::from_secs(1))).is_err());
    assert_eq!(identity(&file), before);
    assert_eq!(fs::read(&file).unwrap(), b"never daemon state");
    let alias = root.path().join("edge.sock");
    symlink(&file, &alias).unwrap();
    let before = identity(&alias);
    assert!(run(bind_inner(&alias, Duration::from_secs(1))).is_err());
    assert_eq!(identity(&alias), before);
    assert_eq!(fs::read(&file).unwrap(), b"never daemon state");
}

#[test]
fn old_runtime_listener_drop_cannot_unlink_a_replacement_endpoint() {
    let root = crate::test_util::private_tempdir();
    let path = root.path().join("edge.sock");
    let listener = run(bind_inner(&path, Duration::from_secs(1))).unwrap();
    fs::rename(&path, root.path().join("retained.sock")).unwrap();
    let replacement = StdListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = identity(&path);
    drop(listener);
    assert_eq!(identity(&path), before);
    assert!(StdStream::connect(&path).is_ok());
    drop(replacement);
}
