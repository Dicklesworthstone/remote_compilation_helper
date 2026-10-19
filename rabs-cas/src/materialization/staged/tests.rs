use super::*;
use crate::blob_store::{BlobStoreLayout, DurabilityPolicy, PutLimits, put_if_absent};
use crate::digest_set::{DigestRequest, digest_set};
use crate::metadata_store::{QuarantineScope, RusqliteEngine, SqlMetadataStore};
use rabs_protocol::raw_bytes::RawBytes;
use std::io::{Seek, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

type Store = SqlMetadataStore<RusqliteEngine>;

struct Fixture {
    root: tempfile::TempDir,
    layout: BlobStoreLayout,
    store: Store,
    outputs: Vec<PlannedActionOutput>,
    freshness: SystemTime,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let layout = BlobStoreLayout::open(&root.path().join("cas")).unwrap();
        let store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        Self {
            root,
            layout,
            store,
            outputs: Vec::new(),
            freshness: SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567_890),
        }
    }

    fn add(&mut self, name: &str, role: OutputRole, bytes: &[u8]) -> PlannedActionOutput {
        let object = digest_set(bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        let mut reader = bytes;
        put_if_absent(
            &self.layout,
            &mut self.store,
            &object,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        let output = PlannedActionOutput {
            role,
            virtual_path: RawBytes::from(name),
            object,
            destination: self.root.path().join("subscriber").join(name),
        };
        self.outputs.push(output.clone());
        output
    }

    fn select(&mut self) -> SelectedActionOutputs {
        SelectedActionOutputs::select(
            &mut self.store,
            &self.outputs,
            MaterializationMode::PrivateCopy,
            self.freshness,
        )
        .unwrap()
    }

    fn old(&self, output: &PlannedActionOutput) {
        std::fs::create_dir_all(output.destination.parent().unwrap()).unwrap();
        std::fs::write(&output.destination, b"previous output").unwrap();
    }

    fn stages(&self) -> usize {
        std::fs::read_dir(self.root.path().join("subscriber"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".rabs-stage-")
            })
            .count()
    }
}

#[test]
fn selection_and_staging_do_not_install_and_final_outputs_are_private_and_ordered() {
    let mut fixture = Fixture::new();
    let tail = fixture.add(
        "liba.rlib",
        OutputRole::Materializable,
        &vec![31; 512 * 1024 + 9],
    );
    let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    fixture.old(&head);
    fixture.old(&tail);
    let selected = fixture.select();
    assert_eq!(fixture.stages(), 0);
    let prepared = selected.stage(&|_, _| Ok(())).unwrap();
    assert_eq!(fixture.stages(), 2);
    for output in [&head, &tail] {
        assert_eq!(
            std::fs::read(&output.destination).unwrap(),
            b"previous output"
        );
    }
    let receipt = prepared.install(&mut fixture.store).unwrap();
    assert_eq!(receipt.installed[0].destination, head.destination);
    assert_eq!(receipt.installed[1].destination, tail.destination);
    assert_eq!(std::fs::read(&head.destination).unwrap(), b"metadata");
    assert_eq!(
        std::fs::read(&tail.destination).unwrap(),
        vec![31; 512 * 1024 + 9]
    );
    assert_eq!(fixture.stages(), 0);
    for output in [&head, &tail] {
        let source = fixture.store.object_locations(&output.object).unwrap()[0]
            .0
            .clone();
        assert_ne!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&output.destination).unwrap().ino()
        );
        assert_eq!(
            std::fs::metadata(&output.destination)
                .unwrap()
                .modified()
                .unwrap(),
            fixture.freshness
        );
        let bytes = std::fs::read(&source).unwrap();
        std::fs::write(&output.destination, b"subscriber mutation").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), bytes);
    }
}

#[test]
fn a_later_corrupt_object_never_exposes_the_earlier_metadata_head() {
    let mut fixture = Fixture::new();
    let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let tail = fixture.add("liba.rlib", OutputRole::Materializable, b"codegen");
    fixture.old(&head);
    fixture.old(&tail);
    let source = fixture.store.object_locations(&tail.object).unwrap()[0]
        .0
        .clone();
    let selected = fixture.select();
    std::fs::write(&source, b"corrupt").unwrap();
    let failure = selected
        .stage(&|_, _| Ok(()))
        .unwrap_err()
        .settle(&mut fixture.store);
    assert!(matches!(
        failure.error,
        MaterializeError::ContentMismatch { .. }
    ));
    assert!(failure.installed.is_empty());
    assert!(
        fixture
            .store
            .object_locations(&tail.object)
            .unwrap()
            .is_empty()
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"corrupt");
    assert_eq!(
        std::fs::read(&head.destination).unwrap(),
        b"previous output"
    );
    assert_eq!(
        std::fs::read(&tail.destination).unwrap(),
        b"previous output"
    );
    assert_eq!(fixture.stages(), 0);
}

#[test]
fn logical_and_location_quarantine_arriving_during_staging_block_every_output() {
    for logical in [false, true] {
        let mut fixture = Fixture::new();
        let head = fixture.add("a.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
        let tail = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
        fixture.old(&head);
        fixture.old(&tail);
        let prepared = fixture.select().stage(&|_, _| Ok(())).unwrap();
        if logical {
            fixture
                .store
                .add_quarantine(
                    QuarantineScope::LogicalObject,
                    &digest_key(&tail.object),
                    "during staging",
                )
                .unwrap();
        } else {
            let source = fixture.store.object_locations(&tail.object).unwrap()[0]
                .0
                .clone();
            fixture
                .store
                .set_location_quarantined(&tail.object, &source, true)
                .unwrap();
        }
        let failure = prepared.install(&mut fixture.store).unwrap_err();
        assert!(failure.installed.is_empty());
        assert!(matches!(
            failure.error,
            MaterializeError::QuarantinedObject { .. } | MaterializeError::NoUsableCopy { .. }
        ));
        for output in [&head, &tail] {
            assert_eq!(
                std::fs::read(&output.destination).unwrap(),
                b"previous output"
            );
        }
        assert_eq!(fixture.stages(), 0);
    }
}

#[test]
fn private_copying_finishes_while_the_actual_metadata_mutex_is_held_elsewhere() {
    let mut fixture = Fixture::new();
    let output = fixture.add(
        "a.rlib",
        OutputRole::Materializable,
        &vec![9; 2 * 1024 * 1024],
    );
    let selected = fixture.select();
    let store = Arc::new(Mutex::new(fixture.store));
    let held = store.lock().unwrap();
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(selected.stage(&|_, _| Ok(()))).unwrap();
    });
    let result = rx.recv_timeout(Duration::from_secs(8));
    // Release and join before asserting, including against a broken version.
    drop(held);
    worker.join().unwrap();
    let prepared = result
        .expect("private staging must not wait for metadata access")
        .unwrap();
    assert!(!output.destination.exists());
    prepared.install(&mut *store.lock().unwrap()).unwrap();
    assert_eq!(
        std::fs::read(output.destination).unwrap(),
        vec![9; 2 * 1024 * 1024]
    );
}

#[test]
fn subscriber_derivation_changes_only_verified_private_bytes_and_reports_new_length() {
    let mut fixture = Fixture::new();
    let output = fixture.add("a.d", OutputRole::DepInfo, b"canonical input record\n");
    let source = fixture.store.object_locations(&output.object).unwrap()[0]
        .0
        .clone();
    let prepared = fixture
        .select()
        .stage(&|out, file| {
            assert_eq!(out.role, OutputRole::DepInfo);
            assert_eq!(file.metadata()?.len(), 23);
            let mut file = file.try_clone()?;
            file.rewind()?;
            file.set_len(0)?;
            file.write_all(b"subscriber\n")
        })
        .unwrap();
    assert!(!output.destination.exists());
    let receipt = prepared.install(&mut fixture.store).unwrap();
    assert_eq!(receipt.installed[0].bytes, 11);
    assert_eq!(std::fs::read(output.destination).unwrap(), b"subscriber\n");
    assert_eq!(std::fs::read(source).unwrap(), b"canonical input record\n");
}

#[test]
fn changed_private_inode_is_refused_and_replacement_evidence_is_not_removed() {
    for replacement in [false, true] {
        let mut fixture = Fixture::new();
        let output = fixture.add("a.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
        fixture.old(&output);
        let prepared = fixture.select().stage(&|_, _| Ok(())).unwrap();
        let stage = &prepared.prepared[0].stage;
        let directory = stage.directory.clone();
        let path = stage.path.clone();
        if replacement {
            std::fs::rename(&path, fixture.root.path().join("retained-object")).unwrap();
        }
        std::fs::write(&path, b"metadata").unwrap();
        let failure = prepared.install(&mut fixture.store).unwrap_err();
        assert!(failure.installed.is_empty());
        assert_eq!(
            std::fs::read(&output.destination).unwrap(),
            b"previous output"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"metadata");
        assert!(directory.exists(), "unknown replacement must be retained");
    }
}

#[test]
fn independent_preparations_never_clean_each_others_private_files() {
    let mut fixture = Fixture::new();
    let output = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
    let first = fixture.select().stage(&|_, _| Ok(())).unwrap();
    let second = fixture.select().stage(&|_, _| Ok(())).unwrap();
    assert_eq!(fixture.stages(), 2);
    drop(first);
    assert_eq!(fixture.stages(), 1);
    assert!(!output.destination.exists());
    second.install(&mut fixture.store).unwrap();
    assert_eq!(fixture.stages(), 0);
    assert_eq!(std::fs::read(output.destination).unwrap(), b"codegen");
}

#[test]
fn derivation_failure_preserves_all_destinations_and_abandons_private_copies() {
    let mut fixture = Fixture::new();
    let head = fixture.add("a.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let tail = fixture.add("a.d", OutputRole::DepInfo, b"dep-info");
    fixture.old(&head);
    fixture.old(&tail);
    let failure = fixture
        .select()
        .stage(&|output, _| {
            if output.role == OutputRole::DepInfo {
                return Err(std::io::Error::other("injected derivation failure"));
            }
            Ok(())
        })
        .unwrap_err()
        .settle(&mut fixture.store);
    assert!(failure.installed.is_empty());
    for output in [&head, &tail] {
        assert_eq!(
            std::fs::read(&output.destination).unwrap(),
            b"previous output"
        );
        assert!(
            !fixture
                .store
                .object_locations(&output.object)
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(fixture.stages(), 0);
}

#[test]
fn final_rename_failure_reports_the_exact_already_installed_prefix() {
    let mut fixture = Fixture::new();
    let head = fixture.add("a.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let tail = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
    let prepared = fixture.select().stage(&|_, _| Ok(())).unwrap();
    std::fs::create_dir(&tail.destination).unwrap();
    let failure = prepared.install(&mut fixture.store).unwrap_err();
    assert_eq!(failure.installed.len(), 1);
    assert_eq!(failure.installed[0].destination, head.destination);
    assert_eq!(std::fs::read(head.destination).unwrap(), b"metadata");
    assert!(tail.destination.is_dir());
    assert_eq!(fixture.stages(), 0);
}

#[test]
fn unsafe_names_and_quarantined_objects_refuse_before_any_private_staging() {
    let mut fixture = Fixture::new();
    let output = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
    for destination in [
        PathBuf::from("relative"),
        fixture.root.path().join("../outside"),
    ] {
        let mut bad = output.clone();
        bad.destination = destination;
        assert!(
            SelectedActionOutputs::select(
                &mut fixture.store,
                &[bad],
                MaterializationMode::PrivateCopy,
                fixture.freshness
            )
            .is_err()
        );
    }
    let duplicate = [output.clone(), output.clone()];
    assert!(
        SelectedActionOutputs::select(
            &mut fixture.store,
            &duplicate,
            MaterializationMode::PrivateCopy,
            fixture.freshness
        )
        .is_err()
    );
    fixture
        .store
        .add_quarantine(
            QuarantineScope::LogicalObject,
            &digest_key(&output.object),
            "before selection",
        )
        .unwrap();
    assert!(
        SelectedActionOutputs::select(
            &mut fixture.store,
            &[output],
            MaterializationMode::PrivateCopy,
            fixture.freshness
        )
        .is_err()
    );
    assert!(!fixture.root.path().join("subscriber").exists());
}

#[test]
fn non_utf8_destinations_remain_distinct_and_lossless() {
    use std::os::unix::ffi::OsStringExt;
    let mut fixture = Fixture::new();
    let output = fixture.add("placeholder", OutputRole::Materializable, b"codegen");
    fixture.outputs.clear();
    for byte in [0xfe, 0xff] {
        let mut output = output.clone();
        output
            .destination
            .set_file_name(std::ffi::OsString::from_vec(vec![b'a', byte]));
        output.virtual_path = RawBytes::new(vec![b'a', byte]);
        fixture.outputs.push(output);
    }
    let prepared = fixture.select().stage(&|_, _| Ok(())).unwrap();
    let receipt = prepared.install(&mut fixture.store).unwrap();
    assert_eq!(receipt.installed.len(), 2);
    for output in fixture.outputs {
        assert_eq!(std::fs::read(output.destination).unwrap(), b"codegen");
    }
}
