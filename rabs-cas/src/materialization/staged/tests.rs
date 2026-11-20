use super::*;
use crate::blob_store::{BlobStoreLayout, DurabilityPolicy, PutLimits, put_if_absent};
use crate::digest_set::{DigestRequest, digest_set};
use crate::metadata_store::{QuarantineScope, RusqliteEngine, SqlEngine, SqlMetadataStore};
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

    fn replica(&mut self, output: &PlannedActionOutput, name: &str, bytes: &[u8]) -> String {
        let path = self.root.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let path = path.to_str().unwrap().to_owned();
        self.store
            .add_location(&output.object, &path, Some(2), RAW_PROFILE_V1, true)
            .unwrap();
        path
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
fn corrupt_replicas_fail_over_and_their_quarantines_survive_reopen() {
    for mode in [
        MaterializationMode::PrivateCopy,
        MaterializationMode::VerifiedCowReflink,
    ] {
        let mut fixture = Fixture::new();
        let metadata_path = fixture.root.path().join("meta.sqlite");
        fixture.store =
            SqlMetadataStore::open(RusqliteEngine::open(&metadata_path).unwrap()).unwrap();
        let bytes = b"verified replica bytes";
        let output = fixture.add("a.rlib", OutputRole::Materializable, bytes);
        fixture.old(&output);
        let primary = fixture.store.object_locations(&output.object).unwrap()[0]
            .0
            .clone();
        std::fs::write(&primary, b"corrupt primary").unwrap();
        let corrupt = fixture.replica(&output, "replica-01-corrupt", b"corrupt replica");
        let healthy = fixture.replica(&output, "replica-02-healthy", bytes);
        let selected = SelectedActionOutputs::select(
            &mut fixture.store,
            &fixture.outputs,
            mode,
            fixture.freshness,
        )
        .unwrap();
        let preparations = std::cell::Cell::new(0);
        let prepared = selected
            .stage(&|_, _| {
                preparations.set(preparations.get() + 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(preparations.get(), 1, "only verified bytes are prepared");
        assert_eq!(
            std::fs::read(&output.destination).unwrap(),
            b"previous output"
        );
        assert_eq!(
            fixture
                .store
                .object_locations(&output.object)
                .unwrap()
                .len(),
            3
        );
        assert_eq!(fixture.stages(), 1);

        let receipt = prepared.install(&mut fixture.store).unwrap();
        assert_eq!(receipt.installed.len(), 1);
        assert_eq!(receipt.installed[0].bytes, bytes.len() as u64);
        assert_eq!(std::fs::read(&output.destination).unwrap(), bytes);
        assert_eq!(fixture.stages(), 0);
        std::fs::write(&output.destination, b"subscriber mutation").unwrap();
        assert_eq!(std::fs::read(&healthy).unwrap(), bytes);

        drop(fixture.store);
        fixture.store =
            SqlMetadataStore::open(RusqliteEngine::open(&metadata_path).unwrap()).unwrap();
        fixture.store.intern_domain(output.object.domain);
        assert_eq!(
            fixture.store.object_locations(&output.object).unwrap(),
            vec![(healthy.clone(), RAW_PROFILE_V1.to_owned(), true)]
        );
        for (path, quarantined) in [(&primary, 1), (&corrupt, 1), (&healthy, 0)] {
            assert_eq!(
                fixture
                    .store
                    .query(
                        "SELECT quarantined FROM object_locations \
                         WHERE object_key = ?1 AND store_path = ?2",
                        &[
                            SqlValue::Text(digest_key(&output.object)),
                            SqlValue::Text(path.clone()),
                        ],
                    )
                    .unwrap(),
                vec![vec![SqlValue::Int(quarantined)]]
            );
        }
        assert!(
            crate::materialization::inspect_quarantine(
                &mut fixture.store,
                QuarantineScope::LogicalObject,
                &digest_key(&output.object),
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(std::fs::read(primary).unwrap(), b"corrupt primary");
        assert_eq!(std::fs::read(corrupt).unwrap(), b"corrupt replica");
    }
}

#[test]
fn corrupt_and_unreadable_replicas_preserve_the_corruption_error_without_exposure() {
    let mut fixture = Fixture::new();
    let output = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
    fixture.old(&output);
    let primary = fixture.store.object_locations(&output.object).unwrap()[0]
        .0
        .clone();
    std::fs::write(&primary, b"corrupt primary").unwrap();
    let corrupt = fixture.replica(&output, "replica-01-corrupt", b"corrupt replica");
    let missing = fixture.root.path().join("replica-02-missing");
    fixture
        .store
        .add_location(
            &output.object,
            missing.to_str().unwrap(),
            Some(2),
            RAW_PROFILE_V1,
            true,
        )
        .unwrap();
    let preparations = std::cell::Cell::new(0);
    let failure = fixture
        .select()
        .stage(&|_, _| {
            preparations.set(preparations.get() + 1);
            Ok(())
        })
        .unwrap_err()
        .settle(&mut fixture.store);
    assert!(matches!(
        failure.error,
        MaterializeError::ContentMismatch { path, .. } if path == primary
    ));
    assert!(failure.installed.is_empty());
    assert_eq!(preparations.get(), 0);
    assert_eq!(
        std::fs::read(&output.destination).unwrap(),
        b"previous output"
    );
    assert_eq!(
        fixture.store.object_locations(&output.object).unwrap(),
        vec![(
            missing.to_str().unwrap().to_owned(),
            RAW_PROFILE_V1.to_owned(),
            true
        )]
    );
    assert_eq!(std::fs::read(primary).unwrap(), b"corrupt primary");
    assert_eq!(std::fs::read(corrupt).unwrap(), b"corrupt replica");
    assert_eq!(fixture.stages(), 0);
}

#[test]
fn explicit_settlement_contains_corruption_when_prepared_outputs_are_abandoned() {
    let mut fixture = Fixture::new();
    let bytes = b"codegen";
    let output = fixture.add("a.rlib", OutputRole::Materializable, bytes);
    fixture.old(&output);
    let primary = fixture.store.object_locations(&output.object).unwrap()[0]
        .0
        .clone();
    std::fs::write(&primary, b"corrupt primary").unwrap();
    let healthy = fixture.replica(&output, "replica-healthy", bytes);
    let mut prepared = fixture.select().stage(&|_, _| Ok(())).unwrap();
    assert_eq!(
        fixture
            .store
            .object_locations(&output.object)
            .unwrap()
            .len(),
        2
    );
    prepared.settle_corruption(&mut fixture.store).unwrap();
    assert_eq!(
        fixture.store.object_locations(&output.object).unwrap(),
        vec![(healthy.clone(), RAW_PROFILE_V1.to_owned(), true)]
    );
    assert_eq!(fixture.stages(), 1);
    assert_eq!(
        std::fs::read(&output.destination).unwrap(),
        b"previous output"
    );
    drop(prepared);
    assert_eq!(fixture.stages(), 0);
    assert_eq!(
        std::fs::read(output.destination).unwrap(),
        b"previous output"
    );
    assert_eq!(std::fs::read(primary).unwrap(), b"corrupt primary");
    assert_eq!(std::fs::read(healthy).unwrap(), bytes);
}

#[test]
fn a_later_output_or_preparation_failure_retains_every_earlier_corruption() {
    for fail_preparation in [false, true] {
        let mut fixture = Fixture::new();
        let head = fixture.add("a.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
        let tail = fixture.add("a.d", OutputRole::DepInfo, b"dep-info");
        fixture.old(&head);
        fixture.old(&tail);
        let head_primary = fixture.store.object_locations(&head.object).unwrap()[0]
            .0
            .clone();
        let tail_primary = fixture.store.object_locations(&tail.object).unwrap()[0]
            .0
            .clone();
        std::fs::write(&head_primary, b"corrupt head").unwrap();
        std::fs::write(&tail_primary, b"corrupt tail").unwrap();
        let healthy_head = fixture.replica(&head, "replica-head", b"metadata");
        if fail_preparation {
            fixture.replica(&tail, "replica-tail-01", b"dep-info");
            fixture.replica(&tail, "replica-tail-02", b"dep-info");
        }
        let head_preparations = std::cell::Cell::new(0);
        let tail_preparations = std::cell::Cell::new(0);
        let failure = fixture
            .select()
            .stage(&|output, _| {
                if output.role == OutputRole::DepInfo {
                    tail_preparations.set(tail_preparations.get() + 1);
                    return Err(std::io::Error::other("subscriber derivation failed"));
                }
                head_preparations.set(head_preparations.get() + 1);
                Ok(())
            })
            .unwrap_err()
            .settle(&mut fixture.store);
        if fail_preparation {
            assert!(matches!(
                failure.error,
                MaterializeError::Io {
                    step: "prepare-staging-metadata",
                    ..
                }
            ));
            assert_eq!(tail_preparations.get(), 1, "derivation must not be retried");
            assert_eq!(
                fixture.store.object_locations(&tail.object).unwrap().len(),
                2
            );
        } else {
            assert!(matches!(
                failure.error,
                MaterializeError::ContentMismatch { path, .. } if path == tail_primary
            ));
            assert_eq!(tail_preparations.get(), 0);
            assert!(
                fixture
                    .store
                    .object_locations(&tail.object)
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(head_preparations.get(), 1);
        assert!(failure.installed.is_empty());
        assert_eq!(
            fixture.store.object_locations(&head.object).unwrap(),
            vec![(healthy_head, RAW_PROFILE_V1.to_owned(), true)]
        );
        for output in [&head, &tail] {
            assert_eq!(
                std::fs::read(&output.destination).unwrap(),
                b"previous output"
            );
        }
        assert_eq!(std::fs::read(head_primary).unwrap(), b"corrupt head");
        assert_eq!(std::fs::read(tail_primary).unwrap(), b"corrupt tail");
        assert_eq!(fixture.stages(), 0);
    }
}

#[test]
fn quarantine_write_failure_refuses_installation_and_still_contains_other_bad_replicas() {
    for healthy_replica in [false, true] {
        let mut fixture = Fixture::new();
        let output = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
        fixture.old(&output);
        let primary = fixture.store.object_locations(&output.object).unwrap()[0]
            .0
            .clone();
        std::fs::write(&primary, b"corrupt primary").unwrap();
        let corrupt = fixture.replica(&output, "replica-01-corrupt", b"corrupt replica");
        let healthy =
            healthy_replica.then(|| fixture.replica(&output, "replica-02-healthy", b"codegen"));
        fixture
            .store
            .engine_mut()
            .execute(
                "CREATE TRIGGER refuse_primary_quarantine \
                 BEFORE UPDATE OF quarantined ON object_locations \
                 WHEN NEW.quarantined = 1 AND NEW.store_path = \
                   (SELECT MIN(store_path) FROM object_locations) \
                 BEGIN SELECT RAISE(ABORT, 'quarantine unavailable'); END",
                &[],
            )
            .unwrap();
        let failure = match fixture.select().stage(&|_, _| Ok(())) {
            Ok(prepared) => {
                assert!(healthy_replica);
                prepared.install(&mut fixture.store).unwrap_err()
            }
            Err(failure) => {
                assert!(!healthy_replica);
                failure.settle(&mut fixture.store)
            }
        };
        assert!(matches!(failure.error, MaterializeError::Store(_)));
        assert!(failure.installed.is_empty());
        let remaining = fixture.store.object_locations(&output.object).unwrap();
        assert_eq!(remaining.len(), 1 + usize::from(healthy_replica));
        assert!(remaining.iter().any(|(path, _, _)| path == &primary));
        assert!(!remaining.iter().any(|(path, _, _)| path == &corrupt));
        if let Some(healthy) = healthy {
            assert!(remaining.iter().any(|(path, _, _)| path == &healthy));
        }
        assert_eq!(
            std::fs::read(&output.destination).unwrap(),
            b"previous output"
        );
        assert_eq!(std::fs::read(primary).unwrap(), b"corrupt primary");
        assert_eq!(std::fs::read(corrupt).unwrap(), b"corrupt replica");
        assert_eq!(fixture.stages(), 0);
    }
}

#[test]
fn failed_explicit_settlement_keeps_observations_for_a_later_retry() {
    let mut fixture = Fixture::new();
    let output = fixture.add("a.rlib", OutputRole::Materializable, b"codegen");
    fixture.old(&output);
    let primary = fixture.store.object_locations(&output.object).unwrap()[0]
        .0
        .clone();
    std::fs::write(&primary, b"corrupt primary").unwrap();
    let healthy = fixture.replica(&output, "replica-healthy", b"codegen");
    let mut prepared = fixture.select().stage(&|_, _| Ok(())).unwrap();
    fixture
        .store
        .engine_mut()
        .execute(
            "CREATE TRIGGER refuse_quarantine BEFORE UPDATE OF quarantined ON object_locations \
             WHEN NEW.quarantined = 1 BEGIN SELECT RAISE(ABORT, 'quarantine unavailable'); END",
            &[],
        )
        .unwrap();
    assert!(matches!(
        prepared.settle_corruption(&mut fixture.store),
        Err(MaterializeError::Store(_))
    ));
    assert_eq!(
        fixture
            .store
            .object_locations(&output.object)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        std::fs::read(&output.destination).unwrap(),
        b"previous output"
    );
    fixture
        .store
        .engine_mut()
        .execute("DROP TRIGGER refuse_quarantine", &[])
        .unwrap();
    prepared.install(&mut fixture.store).unwrap();
    assert_eq!(std::fs::read(output.destination).unwrap(), b"codegen");
    assert_eq!(
        fixture.store.object_locations(&output.object).unwrap(),
        vec![(healthy, RAW_PROFILE_V1.to_owned(), true)]
    );
    assert_eq!(std::fs::read(primary).unwrap(), b"corrupt primary");
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
