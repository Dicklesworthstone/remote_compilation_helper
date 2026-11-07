/// A temporary directory that is private to its owner, whatever the
/// host's umask is.
///
/// Unit tests that mount a temp root DIRECTLY need this. Under rch a
/// worker's TMPDIR points into the workspace, and on a host whose
/// default umask is group-writable — 0002, the Debian/Ubuntu default
/// for user-private groups — the directory comes out 0775.
/// `mount_and_reconcile` then refuses it, correctly: a CAS root that
/// anyone in the group can write is exactly what that check exists to
/// reject.
///
/// The product is right and the fixture was wrong. Without this the
/// suite passes on fleet workers whose umask is 0022 and fails on the
/// ones whose umask is 0002, which is indistinguishable from a real
/// regression until you check the host.
pub fn private_tempdir() -> tempfile::TempDir {
    let parent = std::fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
    let dir = tempfile::tempdir_in(parent).expect("temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private temp dir");
    }
    dir
}

/// A structurally closed regular ar containing an ELF64 relocatable object.
/// The supplied marker is preserved in its own `.data` section, so model tests
/// keep their byte-identity and corruption controls. This is explicitly a
/// container fixture, not evidence of Rust compilation or linkable Rust code.
/// Every result passes the production archive validator before a test can use
/// its digest as validated-closure evidence.
pub fn closed_rlib_fixture(marker: &[u8]) -> Vec<u8> {
    let names = b"\0.data\0.shstrtab\0";
    let mut object = vec![0_u8; 64];
    object[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    object[16..18].copy_from_slice(&1_u16.to_le_bytes());
    object[18..20].copy_from_slice(&62_u16.to_le_bytes());
    object[20..24].copy_from_slice(&1_u32.to_le_bytes());
    object[52..54].copy_from_slice(&64_u16.to_le_bytes());
    object[58..60].copy_from_slice(&64_u16.to_le_bytes());
    object[60..62].copy_from_slice(&3_u16.to_le_bytes());
    object[62..64].copy_from_slice(&2_u16.to_le_bytes());
    object.extend_from_slice(marker);
    let names_offset = object.len();
    object.extend_from_slice(names);
    object.resize(object.len().next_multiple_of(8), 0);
    let table = object.len();
    object[40..48].copy_from_slice(&(table as u64).to_le_bytes());
    // A null section, the marker's .data section, and the names string table.
    object.resize(table + 3 * 64, 0);
    for (index, name, kind, offset, size) in [
        (1, 1_u32, 1_u32, 64, marker.len()),
        (2, 7_u32, 3_u32, names_offset, names.len()),
    ] {
        let section = table + index * 64;
        object[section..section + 4].copy_from_slice(&name.to_le_bytes());
        object[section + 4..section + 8].copy_from_slice(&kind.to_le_bytes());
        object[section + 24..section + 32].copy_from_slice(&(offset as u64).to_le_bytes());
        object[section + 32..section + 40].copy_from_slice(&(size as u64).to_le_bytes());
        object[section + 48..section + 56].copy_from_slice(&1_u64.to_le_bytes());
    }
    let header = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        "fixture.o/",
        0,
        0,
        0,
        "644",
        object.len()
    );
    assert_eq!(header.len(), 60);
    let mut archive = b"!<arch>\n".to_vec();
    archive.extend_from_slice(header.as_bytes());
    archive.extend_from_slice(&object);
    if object.len() & 1 != 0 {
        archive.push(b'\n');
    }
    rabs_sandbox::native_archive::validate_rlib_native_closure(&archive)
        .expect("closed model archive fixture");
    archive
}

/// Establish the same versioned receipt as a successful capture, after checking
/// the fixture's actual bytes and their exact typed content digest. Integration
/// suites include this file directly because private coordinator helpers are
/// intentionally absent from the daemon's public API.
pub fn record_rlib_fixture_closure(
    store: &mut dyn rabs_cas::metadata_store::RabsMetadataStore,
    object: &rabs_protocol::result_identity::TypedDigest,
    bytes: &[u8],
) {
    use rabs_cas::digest_set::{DigestRequest, digest_set};
    use rabs_cas::metadata_store::digest_key;
    use rabs_sandbox::native_archive::{
        NATIVE_ARCHIVE_CLOSURE_CONTRACT, validate_rlib_native_closure,
    };

    validate_rlib_native_closure(bytes).expect("fixture must have a closed native archive");
    let actual = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    assert_eq!(&actual, object, "fixture receipt must bind the exact bytes");
    store
        .record_decision_receipt(
            "native-rlib-closure-v1",
            &digest_key(object),
            0,
            "closed",
            NATIVE_ARCHIVE_CLOSURE_CONTRACT,
        )
        .unwrap();
}
