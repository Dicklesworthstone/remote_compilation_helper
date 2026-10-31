//! The bulk tail remains unstaged while metadata and dep-info are installed.
//! These tests exercise SQLite-backed selection, ordinary CAS bytes and actual
//! file installation; callback/transcript authority belongs to the coordinator.

use super::*;
use crate::blob_store::{BlobStoreLayout, DurabilityPolicy, PutLimits, put_if_absent};
use crate::digest_set::{DigestRequest, digest_set};
use crate::metadata_store::{QuarantineScope, RusqliteEngine, SqlMetadataStore};
use rabs_protocol::raw_bytes::RawBytes;
use std::time::Duration;

struct Fixture {
    root: tempfile::TempDir,
    layout: BlobStoreLayout,
    store: SqlMetadataStore<RusqliteEngine>,
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
        put_if_absent(
            &self.layout,
            &mut self.store,
            &object,
            &mut &bytes[..],
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

    fn stages(&self) -> usize {
        match std::fs::read_dir(self.root.path().join("subscriber")) {
            Ok(entries) => entries
                .map(Result::unwrap)
                .filter(|entry| {
                    entry
                        .file_name()
                        .as_encoded_bytes()
                        .starts_with(b".rabs-stage-")
                })
                .count(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => panic!("cannot inspect owned staging: {error}"),
        }
    }

    fn source(&mut self, output: &PlannedActionOutput) -> String {
        self.store.object_locations(&output.object).unwrap()[0]
            .0
            .clone()
    }
}

#[test]
fn metadata_and_dep_info_are_installed_while_the_exact_bulk_tail_remains_unstaged() {
    let mut fixture = Fixture::new();
    let archive = vec![0x53; 2 * 1024 * 1024 + 7];
    let tail = fixture.add("liba.rlib", OutputRole::Materializable, &archive);
    let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let dep_info = fixture.add("a.d", OutputRole::DepInfo, b"liba.rmeta: input.rs\n");
    let head_source = fixture.source(&head);
    let dep_info_source = fixture.source(&dep_info);
    let tail_source = fixture.source(&tail);
    let (head_selection, tail_selection) = fixture.select().split_metadata();
    assert_eq!(fixture.stages(), 0);
    let selected_head = head_selection.unwrap();
    assert_eq!(selected_head.mode, MaterializationMode::PrivateCopy);
    assert_eq!(selected_head.freshness, fixture.freshness);
    assert_eq!(selected_head.selected.len(), 2);
    assert_eq!(selected_head.selected[0].locations, [head_source.clone()]);
    assert_eq!(
        selected_head.selected[1].locations,
        [dep_info_source.clone()]
    );
    assert_eq!(tail_selection.mode, MaterializationMode::PrivateCopy);
    assert_eq!(tail_selection.freshness, fixture.freshness);
    assert_eq!(tail_selection.selected[0].locations, [tail_source.clone()]);
    let prepared_head = selected_head.stage(&|_, _| Ok(())).unwrap();
    assert_eq!(fixture.stages(), 2);
    assert!(!head.destination.exists());
    assert!(!dep_info.destination.exists());
    assert!(!tail.destination.exists());
    let receipt = prepared_head.install(&mut fixture.store).unwrap();
    assert_eq!(receipt.installed.len(), 2);
    assert_eq!(receipt.installed[0].destination, head.destination);
    assert_eq!(receipt.installed[1].destination, dep_info.destination);
    assert_eq!(std::fs::read(&head.destination).unwrap(), b"metadata");
    assert_eq!(
        std::fs::read(&dep_info.destination).unwrap(),
        b"liba.rmeta: input.rs\n"
    );
    assert!(!tail.destination.exists());
    assert_eq!(
        fixture.stages(),
        0,
        "the tail has no hidden private copy yet"
    );
    let receipt = tail_selection
        .stage(&|_, _| Ok(()))
        .unwrap()
        .install(&mut fixture.store)
        .unwrap();
    assert_eq!(receipt.installed.len(), 1);
    assert_eq!(receipt.installed[0].destination, tail.destination);
    assert_eq!(std::fs::read(&tail.destination).unwrap(), archive);
    for (output, source) in [
        (&head, &head_source),
        (&dep_info, &dep_info_source),
        (&tail, &tail_source),
    ] {
        let metadata = std::fs::metadata(&output.destination).unwrap();
        assert_eq!(metadata.modified().unwrap(), fixture.freshness);
        assert_ne!(metadata.ino(), std::fs::metadata(source).unwrap().ino());
    }
    assert_eq!(fixture.stages(), 0);
}

#[test]
fn corrupt_tail_is_quarantined_without_replacing_or_undoing_the_exposed_head() {
    let mut fixture = Fixture::new();
    let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let tail = fixture.add("liba.rlib", OutputRole::Materializable, b"archive");
    let tail_source = fixture.source(&tail);
    let (head_selection, tail_selection) = fixture.select().split_metadata();
    head_selection
        .unwrap()
        .stage(&|_, _| Ok(()))
        .unwrap()
        .install(&mut fixture.store)
        .unwrap();
    std::fs::write(&tail.destination, b"old target archive").unwrap();
    std::fs::write(&tail_source, b"corrupt").unwrap();
    let failure = tail_selection
        .stage(&|_, _| Ok(()))
        .unwrap_err()
        .settle(&mut fixture.store);
    assert!(matches!(
        failure.error,
        MaterializeError::ContentMismatch { .. }
    ));
    assert!(
        failure.installed.is_empty(),
        "this receipt describes the tail only"
    );
    assert!(
        fixture
            .store
            .object_locations(&tail.object)
            .unwrap()
            .is_empty()
    );
    assert_eq!(std::fs::read(&head.destination).unwrap(), b"metadata");
    assert_eq!(
        std::fs::read(&tail.destination).unwrap(),
        b"old target archive"
    );
    assert_eq!(std::fs::read(&tail_source).unwrap(), b"corrupt");
    assert_eq!(fixture.stages(), 0);
}

#[test]
fn tail_rechecks_selected_location_and_logical_quarantine_after_metadata_install() {
    for logical in [false, true] {
        let mut fixture = Fixture::new();
        let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
        let tail = fixture.add("liba.rlib", OutputRole::Materializable, b"archive");
        let original = fixture.source(&tail);
        let (head_selection, tail_selection) = fixture.select().split_metadata();
        head_selection
            .unwrap()
            .stage(&|_, _| Ok(()))
            .unwrap()
            .install(&mut fixture.store)
            .unwrap();
        let prepared_tail = tail_selection.stage(&|_, _| Ok(())).unwrap();
        if logical {
            fixture
                .store
                .add_quarantine(
                    QuarantineScope::LogicalObject,
                    &digest_key(&tail.object),
                    "quarantined after metadata exposure",
                )
                .unwrap();
        } else {
            // A fresh usable copy does not substitute for the exact location
            // selected before the head. Its private tail must still refuse.
            let replacement = fixture.root.path().join("replacement-archive");
            std::fs::copy(&original, &replacement).unwrap();
            fixture
                .store
                .add_location(
                    &tail.object,
                    replacement.to_str().unwrap(),
                    None,
                    RAW_PROFILE_V1,
                    false,
                )
                .unwrap();
            fixture
                .store
                .set_location_quarantined(&tail.object, &original, true)
                .unwrap();
        }
        let failure = prepared_tail.install(&mut fixture.store).unwrap_err();
        assert!(matches!(
            failure.error,
            MaterializeError::QuarantinedObject { .. } | MaterializeError::NoUsableCopy { .. }
        ));
        assert!(failure.installed.is_empty());
        assert_eq!(std::fs::read(&head.destination).unwrap(), b"metadata");
        assert!(!tail.destination.exists());
        assert_eq!(fixture.stages(), 0);
    }
}

#[test]
fn replaced_private_tail_is_retained_as_evidence_and_never_installed() {
    let mut fixture = Fixture::new();
    let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
    let tail = fixture.add("liba.rlib", OutputRole::Materializable, b"archive");
    let (head_selection, tail_selection) = fixture.select().split_metadata();
    head_selection
        .unwrap()
        .stage(&|_, _| Ok(()))
        .unwrap()
        .install(&mut fixture.store)
        .unwrap();
    let prepared_tail = tail_selection.stage(&|_, _| Ok(())).unwrap();
    let stage = &prepared_tail.prepared[0].stage;
    let path = stage.path.clone();
    let directory = stage.directory.clone();
    std::fs::rename(&path, fixture.root.path().join("retained-tail")).unwrap();
    std::fs::write(&path, b"archive").unwrap();
    assert!(
        prepared_tail
            .install(&mut fixture.store)
            .unwrap_err()
            .installed
            .is_empty()
    );
    assert_eq!(std::fs::read(&head.destination).unwrap(), b"metadata");
    assert!(!tail.destination.exists());
    assert_eq!(std::fs::read(&path).unwrap(), b"archive");
    assert!(directory.exists());
}

#[test]
fn empty_and_nonmetadata_selections_keep_the_complete_normal_path() {
    let mut fixture = Fixture::new();
    let (head, tail) = fixture.select().split_metadata();
    assert!(head.is_none());
    assert!(tail.is_empty());
    assert!(
        tail.stage(&|_, _| Ok(()))
            .unwrap()
            .install(&mut fixture.store)
            .unwrap()
            .installed
            .is_empty()
    );
    assert!(!fixture.root.path().join("subscriber").exists());
    let dep_info = fixture.add(
        "ordinary.d",
        OutputRole::DepInfo,
        b"ordinary.rlib: input.rs\n",
    );
    // File spelling never substitutes for the committed logical role.
    let ordinary = fixture.add("named.rmeta", OutputRole::Materializable, b"ordinary bytes");
    let (head, tail) = fixture.select().split_metadata();
    assert!(head.is_none());
    assert!(!tail.is_empty());
    let receipt = tail
        .stage(&|_, _| Ok(()))
        .unwrap()
        .install(&mut fixture.store)
        .unwrap();
    assert_eq!(receipt.installed.len(), 2);
    assert_eq!(
        std::fs::read(&ordinary.destination).unwrap(),
        b"ordinary bytes"
    );
    assert_eq!(
        std::fs::read(&dep_info.destination).unwrap(),
        b"ordinary.rlib: input.rs\n"
    );
}

#[test]
fn complete_selection_rejects_cross_phase_aliases_and_unavailable_tail_before_staging() {
    for unavailable in [false, true] {
        let mut fixture = Fixture::new();
        let head = fixture.add("liba.rmeta", OutputRole::ProvisionalMetadata, b"metadata");
        let tail = fixture.add("liba.rlib", OutputRole::Materializable, b"archive");
        if unavailable {
            let source = fixture.source(&tail);
            fixture
                .store
                .set_location_quarantined(&tail.object, &source, true)
                .unwrap();
        } else {
            fixture.outputs[1].destination = head.destination;
        }
        assert!(
            SelectedActionOutputs::select(
                &mut fixture.store,
                &fixture.outputs,
                MaterializationMode::PrivateCopy,
                fixture.freshness
            )
            .is_err()
        );
        assert!(!fixture.root.path().join("subscriber").exists());
    }
}
