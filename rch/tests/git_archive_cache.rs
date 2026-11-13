//! Cache bypass must still repair a receiver with the same size and timestamp.
//! Native cache lifecycle and fault tests live with the worker implementation.
#[cfg(unix)]
#[test]
fn git_archive_cache_fallback_repairs_equal_size_equal_mtime_corrupt_receivers() {
    use std::fs::{self, File, FileTimes};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    use std::time::{Duration, SystemTime};

    let fixtures = tempfile::tempdir().unwrap().keep();
    let payload: Vec<u8> = (0..20_480).map(|index| (index % 251) as u8).collect();
    let sender = fixtures.join("selected archive");
    fs::write(&sender, &payload).unwrap();
    fs::set_permissions(&sender, fs::Permissions::from_mode(0o600)).unwrap();
    let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    File::open(&sender)
        .unwrap()
        .set_times(FileTimes::new().set_modified(timestamp))
        .unwrap();
    let mut damaged = payload.clone();
    *damaged.last_mut().unwrap() ^= 1;
    for integrity in ["--checksum", "--ignore-times"] {
        let receiver = fixtures.join(format!("cache receiver {integrity}"));
        fs::write(&receiver, &damaged).unwrap();
        fs::set_permissions(&receiver, fs::Permissions::from_mode(0o600)).unwrap();
        File::open(&receiver)
            .unwrap()
            .set_times(FileTimes::new().set_modified(timestamp))
            .unwrap();
        let before = fs::metadata(&receiver).unwrap();
        let selected = fs::metadata(&sender).unwrap();
        assert_eq!(before.len(), selected.len());
        assert_eq!(before.modified().unwrap(), selected.modified().unwrap());
        let output = Command::new("rsync")
            .args(["-a", "--no-owner", "--no-group", "--partial", integrity])
            .arg(&sender)
            .arg(&receiver)
            .output()
            .expect("rsync is required for the native transfer integrity regression");
        assert!(output.status.success(), "{integrity}: {output:?}");
        assert!(output.stderr.is_empty(), "{integrity}: {output:?}");
        assert_eq!(fs::read(receiver).unwrap(), payload, "{integrity}");
    }
}
