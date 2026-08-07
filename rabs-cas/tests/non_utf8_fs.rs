//! Non-UTF8 storage/materialization round-trip on the REAL
//! filesystem — the fs half of bead T026 (risk R89).
//!
//! Symlink targets and file names are byte strings on Unix. These
//! fixtures write them through `std::fs`, read them back, and assert
//! BYTE equality — no lossy decode anywhere in the loop. Platform
//! honesty: APFS (macOS) rejects some non-UTF8 file NAMES at
//! creation; the fixtures accept an explicit OS refusal (a typed
//! platform fact) but never a silent byte alteration.

#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const CAFE_UTF8: &[u8] = b"caf\xC3\xA9";
const CAFE_LATIN1: &[u8] = b"caf\xE9";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rabs_t026_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn symlink_targets_round_trip_byte_exactly() {
    // The symlink TARGET is stored bytes: write a non-UTF8 target,
    // read it back, compare bytes.
    let dir = scratch("symlink");
    let link = dir.join("the-link");
    let target = OsStr::from_bytes(b"../objects/caf\xE9-\xFF\xFEtarget");
    std::os::unix::fs::symlink(target, &link).expect("symlink creation stores raw bytes");
    let read_back = std::fs::read_link(&link).expect("read_link");
    assert_eq!(
        read_back.as_os_str().as_bytes(),
        target.as_bytes(),
        "symlink target bytes must survive storage exactly"
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn file_names_are_never_silently_altered() {
    // NFC vs NFD "café": both valid UTF-8, DIFFERENT bytes. A
    // byte-preserving filesystem must keep them distinct spellings.
    let dir = scratch("names");
    let nfc = OsStr::from_bytes(CAFE_UTF8); // U+00E9 precomposed
    let nfd = OsStr::from_bytes(b"cafe\xCC\x81"); // e + combining acute
    std::fs::write(dir.join(nfc), b"nfc-content").expect("nfc name");
    std::fs::write(dir.join(nfd), b"nfd-content").expect("nfd name");
    // Read back through directory enumeration: every observed name
    // must be byte-identical to one we wrote (some filesystems store
    // one canonical spelling for both — that is an aliasing fact the
    // capture layer must SEE, never a silent byte rewrite of a name
    // we then misreport).
    let observed: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().as_bytes().to_vec())
        .collect();
    for name in &observed {
        assert!(
            name.as_slice() == CAFE_UTF8 || name.as_slice() == b"cafe\xCC\x81",
            "observed a name spelling we never wrote: {name:?}"
        );
    }
    assert!(!observed.is_empty());
    // Raw Latin-1 name: APFS refuses non-UTF8 names, ext4 accepts
    // them. EITHER outcome is honest; silent alteration is not.
    let latin1 = OsStr::from_bytes(CAFE_LATIN1);
    match std::fs::write(dir.join(latin1), b"latin1-content") {
        Ok(()) => {
            let found = std::fs::read_dir(&dir)
                .expect("read_dir")
                .map(|e| e.expect("entry").file_name().as_bytes().to_vec())
                .any(|n| n == CAFE_LATIN1);
            assert!(found, "created non-UTF8 name must read back byte-exactly");
        }
        Err(err) => {
            // The typed platform refusal (macOS/APFS): an explicit
            // error, not a mangled name.
            assert!(
                err.kind() == std::io::ErrorKind::InvalidInput || err.raw_os_error().is_some(),
                "refusal must be an explicit OS error, got {err:?}"
            );
        }
    }
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn file_content_bytes_round_trip_exactly() {
    // Storage/materialization of CONTENT is byte-exact for every
    // byte value 0..=255.
    let dir = scratch("content");
    let all_bytes: Vec<u8> = (0..=255u8).collect();
    let path = dir.join("all-bytes.bin");
    std::fs::write(&path, &all_bytes).expect("write");
    let read_back = std::fs::read(&path).expect("read");
    assert_eq!(read_back, all_bytes);
    std::fs::remove_dir_all(&dir).expect("cleanup");
}
