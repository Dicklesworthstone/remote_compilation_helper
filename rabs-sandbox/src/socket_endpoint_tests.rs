use super::*;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};

fn directory() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn private_socket(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

fn connection_refused() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, "probe fixture")
}

#[test]
fn acquisition_excludes_parallel_owners_but_not_other_endpoints() {
    let root = directory();
    let path = root.path().join("edge.sock");
    let first = EndpointLease::acquire(&path).unwrap();
    let lock_identity = inode(&first.lock.0.metadata().unwrap());
    assert!(EndpointLease::acquire(&path).is_err());
    let other = EndpointLease::acquire(&root.path().join("other.sock")).unwrap();
    drop(other);
    drop(first);
    let second = EndpointLease::acquire(&path).unwrap();
    assert_eq!(inode(&second.lock.0.metadata().unwrap()), lock_identity);
    assert!(second.observe().unwrap().is_none());
}

#[test]
fn stale_recovery_requires_a_real_refused_connect_and_keeps_the_lock_inode() {
    let root = directory();
    let path = root.path().join("edge.sock");
    drop(private_socket(&path));
    let mut lease = EndpointLease::acquire(&path).unwrap();
    let observed = lease.observe().unwrap().unwrap();
    let error = UnixStream::connect(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    lease.retire_refused(observed, &error).unwrap();
    assert!(fs::symlink_metadata(&path).is_err());
    assert!(lease.parent.join(&lease.lock_name).is_file());
    let listener = UnixListener::bind(&path).unwrap();
    lease.claim_bound().unwrap();
    assert!(UnixStream::connect(&path).is_ok());
    drop(listener);
    assert!(lease.retire_bound().unwrap());
    assert!(!lease.retire_bound().unwrap());
}

#[test]
fn uncertain_probe_results_never_retire_even_a_dead_socket() {
    let root = directory();
    let path = root.path().join("edge.sock");
    drop(private_socket(&path));
    let lease = EndpointLease::acquire(&path).unwrap();
    let observed = lease.observe().unwrap().unwrap();
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::Interrupted,
        io::ErrorKind::NotFound,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::Other,
    ] {
        assert!(
            lease
                .retire_refused(observed, &io::Error::from(kind))
                .is_err()
        );
        assert_eq!(lease.observe().unwrap(), Some(observed));
    }
}

#[test]
fn changed_probe_generation_is_not_retired() {
    let root = directory();
    let path = root.path().join("edge.sock");
    drop(private_socket(&path));
    let lease = EndpointLease::acquire(&path).unwrap();
    let observed = lease.observe().unwrap().unwrap();
    fs::rename(&path, root.path().join("retained.sock")).unwrap();
    let replacement = private_socket(&path);
    assert!(
        lease
            .retire_refused(observed, &connection_refused())
            .is_err()
    );
    assert!(UnixStream::connect(&path).is_ok());
    drop(replacement);
}

#[test]
fn unclaimed_lease_drop_never_deletes_a_live_or_stale_socket() {
    let root = directory();
    let path = root.path().join("edge.sock");
    let listener = private_socket(&path);
    let lease = EndpointLease::acquire(&path).unwrap();
    let original = lease.observe().unwrap();
    drop(lease);
    assert!(UnixStream::connect(&path).is_ok());
    drop(listener);
    let lease = EndpointLease::acquire(&path).unwrap();
    assert_eq!(lease.observe().unwrap(), original);
    drop(lease);
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
}

#[test]
fn teardown_preserves_replacement_socket_and_regular_file() {
    for socket in [false, true] {
        let root = directory();
        let path = root.path().join("edge.sock");
        let mut lease = EndpointLease::acquire(&path).unwrap();
        let original = UnixListener::bind(&path).unwrap();
        lease.claim_bound().unwrap();
        drop(original);
        fs::rename(&path, root.path().join("old.sock")).unwrap();
        let replacement = if socket {
            Some(private_socket(&path))
        } else {
            fs::write(&path, b"not daemon state").unwrap();
            None
        };
        assert!(!lease.retire_bound().unwrap_or(false));
        drop(lease);
        if socket {
            assert!(UnixStream::connect(&path).is_ok());
        } else {
            assert_eq!(fs::read(&path).unwrap(), b"not daemon state");
        }
        drop(replacement);
    }
}

#[test]
fn symlink_and_hardlinked_sockets_are_never_reclaimed_or_chmodded() {
    let root = directory();
    let original = root.path().join("original.sock");
    let listener = private_socket(&original);
    let alias = root.path().join("alias.sock");
    symlink(&original, &alias).unwrap();
    let mut lease = EndpointLease::acquire(&alias).unwrap();
    assert!(lease.observe().is_err());
    assert!(lease.claim_bound().is_err());
    assert!(
        fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let hardlink = root.path().join("hardlink.sock");
    fs::hard_link(&original, &hardlink).unwrap();
    let mut lease = EndpointLease::acquire(&hardlink).unwrap();
    assert!(lease.observe().is_err());
    assert!(lease.claim_bound().is_err());
    assert!(UnixStream::connect(&original).is_ok());
    drop(listener);
}

#[test]
fn endpoint_aliases_share_ownership_and_retargeting_revokes_mutation() {
    let root = directory();
    let real = root.path().join("real");
    let other = root.path().join("other");
    fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&other).unwrap();
    let alias = root.path().join("alias");
    symlink(&real, &alias).unwrap();
    let mut lease = EndpointLease::acquire(&alias.join("edge.sock")).unwrap();
    let listener = UnixListener::bind(lease.path()).unwrap();
    lease.claim_bound().unwrap();
    assert!(EndpointLease::acquire(&real.join("edge.sock")).is_err());
    fs::rename(&alias, root.path().join("retained-alias")).unwrap();
    symlink(&other, &alias).unwrap();
    assert!(lease.verify().is_err());
    assert!(lease.retire_bound().is_err());
    assert!(UnixStream::connect(real.join("edge.sock")).is_ok());
    drop(listener);
}

#[test]
fn replacing_a_parent_or_lock_prevents_old_owner_cleanup() {
    for replace_parent in [false, true] {
        let root = directory();
        let parent = root.path().join("state");
        let path = parent.join("edge.sock");
        let mut lease = EndpointLease::acquire(&path).unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        lease.claim_bound().unwrap();
        if replace_parent {
            fs::rename(&parent, root.path().join("retained-state")).unwrap();
            fs::create_dir(&parent).unwrap();
            fs::write(&path, b"replacement").unwrap();
        } else {
            let lock_path = parent.join(&lease.lock_name);
            fs::rename(&lock_path, parent.join("retained.lock")).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&lock_path)
                .unwrap();
        }
        assert!(lease.verify().is_err());
        assert!(lease.retire_bound().is_err());
        assert!(fs::symlink_metadata(&path).is_ok());
        drop(listener);
    }
}

#[test]
fn insecure_parent_or_lock_is_refused_without_repair() {
    let root = directory();
    let parent = root.path().join("shared");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(EndpointLease::acquire(&parent.join("edge.sock")).is_err());
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    let target = root.path().join("important");
    fs::write(&target, b"preserve").unwrap();
    let lock = root.path().join(".rabs-edge.sock.endpoint.lock");
    symlink(&target, &lock).unwrap();
    assert!(EndpointLease::acquire(&root.path().join("edge.sock")).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"preserve");
    assert!(
        fs::symlink_metadata(&lock)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn explicit_unlock_releases_even_with_a_duplicate_file_description() {
    let root = directory();
    let path = root.path().join("edge.sock");
    let lease = EndpointLease::acquire(&path).unwrap();
    let duplicate = lease.lock.0.try_clone().unwrap();
    drop(lease);
    let successor = EndpointLease::acquire(&path).unwrap();
    assert_eq!(
        inode(&duplicate.metadata().unwrap()),
        inode(&successor.lock.0.metadata().unwrap()),
    );
    drop(duplicate);
    // Closing an old duplicate cannot release the successor's new open description.
    assert!(EndpointLease::acquire(&path).is_err());
}

#[test]
fn raw_names_sibling_churn_and_permanent_locks_do_not_invalidate_ownership() {
    let root = directory();
    let path = root
        .path()
        .join(OsString::from_vec(b"edge-\xff.sock".to_vec()));
    let mut lease = EndpointLease::acquire(&path).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    lease.claim_bound().unwrap();
    fs::write(root.path().join("unrelated"), b"sibling churn").unwrap();
    fs::create_dir(root.path().join("cargo-launcher")).unwrap();
    lease.verify().unwrap();
    let lock = lease.parent.join(&lease.lock_name);
    drop(listener);
    assert!(lease.retire_bound().unwrap());
    drop(lease);
    assert!(lock.is_file());
    assert!(EndpointLease::acquire(&path).is_ok());
}

#[test]
fn traversal_and_repeated_binding_never_authorize_retirement() {
    let root = directory();
    for path in [
        PathBuf::from("relative.sock"),
        PathBuf::from("/"),
        root.path().join("x/../edge.sock"),
    ] {
        assert!(EndpointLease::acquire(&path).is_err());
    }
    assert!(!root.path().join("x").exists());
    let path = root.path().join("edge.sock");
    let mut lease = EndpointLease::acquire(&path).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    lease.claim_bound().unwrap();
    assert!(lease.claim_bound().is_err());
    let observed = lease.observe().unwrap().unwrap();
    assert!(
        lease
            .retire_refused(observed, &connection_refused())
            .is_err()
    );
    assert!(UnixStream::connect(&path).is_ok());
    drop(listener);
}
