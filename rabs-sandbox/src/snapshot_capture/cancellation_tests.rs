use super::*;
use std::cell::Cell;

#[test]
fn stopped_capture_refuses_before_source_namespace_access() {
    let retained = tempfile::tempdir().unwrap().keep();
    let missing = retained.join("missing-source");
    let result = capture_sealed_source_cancellable(
        &[("workspace".to_string(), missing.clone())],
        false,
        3,
        1024,
        || true,
    );
    assert!(matches!(result, Err(CaptureError::Cancelled)));
    assert!(!missing.exists());
}

#[test]
fn cancellation_during_a_real_read_stops_after_one_chunk_without_altering_source() {
    let retained = tempfile::tempdir().unwrap().keep();
    let path = retained.join("source.rs");
    let source = vec![b'x'; CAPTURE_IO_CHUNK_BYTES * 3 + 17];
    std::fs::write(&path, &source).unwrap();
    let observed = std::fs::symlink_metadata(&path).unwrap();
    let stopped = Cell::new(false);
    let chunks = Cell::new(0);
    let mut remaining = source.len() as u64;

    let result = read_retained_file_with_cancellation(
        &path,
        "source.rs",
        &observed,
        &mut remaining,
        |count| {
            assert_eq!(count, CAPTURE_IO_CHUNK_BYTES);
            chunks.set(chunks.get() + 1);
            stopped.set(true);
        },
        &|| stopped.get(),
    );
    assert!(matches!(result, Err(CaptureError::Cancelled)));
    assert_eq!(chunks.get(), 1);
    assert_eq!(remaining, (source.len() - CAPTURE_IO_CHUNK_BYTES) as u64);
    assert_eq!(std::fs::read(&path).unwrap(), source);

    // A later request can still seal the complete unchanged source, and the
    // incremental read hash remains the ordinary SHA-256 of the retained bytes.
    let image = capture_sealed_source(
        &[("workspace".to_string(), retained)],
        false,
        1,
        source.len() as u64,
    )
    .unwrap();
    assert_eq!(
        image.file_bytes("workspace", "source.rs"),
        Some(source.as_slice())
    );
    let MemberKind::Regular { content_sha256, .. } =
        &image.manifest("workspace").unwrap().members["source.rs"]
    else {
        panic!("real source was not retained as a regular file");
    };
    let expected: [u8; 32] = Sha256::digest(&source).into();
    assert_eq!(*content_sha256, expected);
}

#[test]
fn cancellation_after_either_real_pass_never_seals_or_retries() {
    for stop_after in [0, 1] {
        let retained = tempfile::tempdir().unwrap().keep();
        let source = retained.join("source.rs");
        std::fs::write(&source, b"unchanged source").unwrap();
        let stopped = Cell::new(false);
        let mut completed_passes = Vec::new();
        let result = capture_sealed_source_with_cancellation(
            &[("workspace".to_string(), retained)],
            false,
            3,
            1024,
            |attempt, pass| {
                completed_passes.push((attempt, pass));
                if pass == stop_after {
                    stopped.set(true);
                }
            },
            &|| stopped.get(),
        );
        assert!(matches!(result, Err(CaptureError::Cancelled)));
        assert_eq!(
            completed_passes,
            (0..=stop_after).map(|pass| (0, pass)).collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"unchanged source");
    }
}

#[test]
fn cancellation_of_a_mutated_real_pair_never_enters_another_attempt() {
    let retained = tempfile::tempdir().unwrap().keep();
    let source = retained.join("source.rs");
    std::fs::write(&source, b"before editor write").unwrap();
    let stopped = Cell::new(false);
    let mut completed_passes = Vec::new();
    let result = capture_sealed_source_with_cancellation(
        &[("workspace".to_string(), retained)],
        false,
        3,
        1024,
        |attempt, pass| {
            completed_passes.push((attempt, pass));
            if pass == 0 {
                std::fs::write(&source, b"after editor write").unwrap();
            } else {
                stopped.set(true);
            }
        },
        &|| stopped.get(),
    );
    assert!(matches!(result, Err(CaptureError::Cancelled)));
    assert_eq!(completed_passes, [(0, 0), (0, 1)]);
    assert_eq!(std::fs::read(&source).unwrap(), b"after editor write");
}

#[test]
fn materialization_stops_at_a_real_written_chunk_without_publishing_a_handle() {
    let retained = tempfile::tempdir().unwrap().keep();
    let checkout = retained.join("checkout");
    std::fs::create_dir(&checkout).unwrap();
    let source = vec![b'y'; CAPTURE_IO_CHUNK_BYTES * 3 + 17];
    std::fs::write(checkout.join("source.rs"), &source).unwrap();
    let image = capture_sealed_source(
        &[("workspace".to_string(), checkout.clone())],
        false,
        1,
        source.len() as u64,
    )
    .unwrap();

    let untouched = retained.join("cancelled-before-start");
    assert!(matches!(
        image.materialize_into_cancellable(&untouched, || true),
        Err(CaptureError::Cancelled)
    ));
    assert!(!untouched.exists());

    let destination = retained.join("cancelled-during-write");
    let partial = destination.join("workspace/source.rs");
    let result = image.materialize_into_cancellable(&destination, || {
        std::fs::metadata(&partial)
            .is_ok_and(|metadata| metadata.len() >= CAPTURE_IO_CHUNK_BYTES as u64)
    });
    assert!(matches!(result, Err(CaptureError::Cancelled)));
    assert_eq!(
        std::fs::read(&partial).unwrap(),
        source[..CAPTURE_IO_CHUNK_BYTES]
    );
    assert_eq!(std::fs::read(checkout.join("source.rs")).unwrap(), source);

    let complete = image.materialize_into(&retained.join("complete")).unwrap();
    assert_eq!(
        std::fs::read(complete.backing("workspace").unwrap().join("source.rs")).unwrap(),
        source
    );
}
