//! Digest-bound evidence that a Rust archive's packed native payloads are
//! closed. A successful rustc exit is insufficient: whole-archive
//! bundling can preserve a thin archive or linker script until a later link.
//!
//! Capture records this fact only after validating the exact private bytes that
//! supply the object digest. Replay requires it for the complete archive output
//! set before exposing even metadata. This keeps metadata-before-tail delivery
//! without trusting old cache entries or inferring native closure from argv.
//! Ordinary publication, quarantine, replica hashing and installation gates
//! remain necessary; this receipt grants none of their authority.

use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue, digest_key};
use rabs_protocol::result_identity::{CanonicalActionResultManifest, DigestAlgorithm, TypedDigest};
use rabs_sandbox::native_archive::NATIVE_ARCHIVE_CLOSURE_CONTRACT;

const RECEIPT_KIND: &str = "native-rlib-closure-v1";
const RECEIPT_SEQUENCE: u64 = 0;
const RECEIPT_DECISION: &str = "closed";

fn object_key(object: &TypedDigest) -> Result<String, String> {
    if object.algorithm != DigestAlgorithm::Sha256V1 || object.domain != ATP_OBJECT_CONTENT_DOMAIN {
        return Err("native archive closure requires an ATP SHA-256 object identity".into());
    }
    Ok(digest_key(object))
}

/// Record the packed-native closure of the immutable bytes identified by `object`.
///
/// The caller must first pass those same retained bytes through
/// `validate_rlib_native_closure_file`, bind them to this content digest, and
/// retain their verified generation through publication. An action key, worker
/// claim, successful compiler exit or prior receipt cannot supply that proof.
/// The fixed sequence makes repeating the same validated capture idempotent;
/// a conflicting receipt is never overwritten.
pub(super) fn record_validated(
    store: &mut dyn RabsMetadataStore,
    object: &TypedDigest,
) -> Result<(), String> {
    let subject = object_key(object)?;
    store
        .record_decision_receipt(
            RECEIPT_KIND,
            &subject,
            RECEIPT_SEQUENCE,
            RECEIPT_DECISION,
            NATIVE_ARCHIVE_CLOSURE_CONTRACT,
        )
        .map_err(|error| format!("record native archive closure: {error:?}"))
}

/// Require current validator evidence for every Rust archive in a result.
///
/// This is a complete-result gate: run it before preview grants a hit and
/// before any metadata or archive is installed. Source `#[link]` attributes can
/// introduce bundled native inputs without a command-line native library, so
/// neither the action class nor argv may narrow this check. Paths only select
/// archive outputs; evidence is always bound to their exact typed byte digest.
pub(super) fn require_manifest(
    store: &mut dyn RabsMetadataStore,
    manifest: &CanonicalActionResultManifest,
) -> Result<(), String> {
    for output in &manifest.logical_outputs {
        if !output.virtual_path.as_bytes().ends_with(b".rlib") {
            continue;
        }
        let subject = object_key(&output.object.0)?;
        // Exact predicates keep old versions and malformed fields from
        // authorizing replay. Return only a bounded marker, never an arbitrary
        // stored reason or decision whose length may have been corrupted.
        let rows = store
            .query(
                "SELECT 1 FROM decision_receipts \
                 WHERE kind = ?1 AND subject = ?2 AND seq = 0 \
                 AND decision = ?3 AND reason = ?4 LIMIT 2",
                &[
                    SqlValue::Text(RECEIPT_KIND.into()),
                    SqlValue::Text(subject),
                    SqlValue::Text(RECEIPT_DECISION.into()),
                    SqlValue::Text(NATIVE_ARCHIVE_CLOSURE_CONTRACT.into()),
                ],
            )
            .map_err(|error| format!("read native archive closure: {error:?}"))?;
        if !matches!(rows.as_slice(), [row] if row.as_slice() == [SqlValue::Int(1)]) {
            return Err("native archive closure receipt is missing or invalid".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_cas::digest_set::{DigestRequest, digest_set};
    use rabs_cas::metadata_store::{RusqliteEngine, SqlEngine, SqlMetadataStore};
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{LogicalOutput, ObjectId, OutputRole};

    fn store() -> SqlMetadataStore<RusqliteEngine> {
        SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()
    }

    fn object(marker: &[u8]) -> TypedDigest {
        let bytes = crate::test_util::closed_rlib_fixture(marker);
        digest_set(&bytes, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id
    }

    fn output(path: &[u8], object: &TypedDigest, role: OutputRole) -> LogicalOutput {
        LogicalOutput {
            role,
            virtual_path: RawBytes::new(path.to_vec()),
            object: ObjectId(object.clone()),
        }
    }

    fn manifest(outputs: Vec<LogicalOutput>) -> CanonicalActionResultManifest {
        let mut manifest = rabs_cas::test_support::sample_manifest();
        manifest.logical_outputs = outputs;
        manifest
    }

    // These tests exercise the real SQLite receipt gate and actual validated
    // container identities. They do not claim compiler execution or H011
    // publication; the capture/publication integration has its own tests.
    #[test]
    fn receipt_follows_exact_object_bytes_across_actions_and_names() {
        let mut store = store();
        let original = object(b"the first already-validated archive");
        let changed = object(b"the changed archive needs its own validation");
        let original_manifest = manifest(vec![output(
            b"liboriginal.rlib",
            &original,
            OutputRole::Materializable,
        )]);
        assert!(require_manifest(&mut store, &original_manifest).is_err());
        record_validated(&mut store, &original).unwrap();
        record_validated(&mut store, &original).unwrap();
        require_manifest(&mut store, &original_manifest).unwrap();

        let mut renamed = original_manifest.clone();
        renamed.action_key.bytes[0] ^= 1;
        renamed.canonical_descriptor_digest.bytes[0] ^= 1;
        renamed.logical_outputs[0].virtual_path = RawBytes::from("other/librenamed.rlib");
        require_manifest(&mut store, &renamed).unwrap();

        let mut changed_manifest = original_manifest;
        changed_manifest.logical_outputs[0].object = ObjectId(changed.clone());
        assert!(require_manifest(&mut store, &changed_manifest).is_err());
        record_validated(&mut store, &changed).unwrap();
        require_manifest(&mut store, &changed_manifest).unwrap();
    }

    #[test]
    fn every_archive_is_required_even_without_native_cli_or_materializable_role() {
        let mut store = store();
        let first = object(b"first validated archive");
        let second = object(b"second validated archive");
        let third = object(b"third validated archive");
        let manifest = manifest(vec![
            output(b"libfirst.rlib", &first, OutputRole::Materializable),
            output(b"out/lib\xff.rlib", &second, OutputRole::Materializable),
            output(b"libthird.rlib", &third, OutputRole::ProvisionalMetadata),
        ]);
        record_validated(&mut store, &first).unwrap();
        assert!(require_manifest(&mut store, &manifest).is_err());
        record_validated(&mut store, &second).unwrap();
        assert!(require_manifest(&mut store, &manifest).is_err());
        record_validated(&mut store, &third).unwrap();
        require_manifest(&mut store, &manifest).unwrap();
    }

    #[test]
    fn old_wrong_or_malformed_receipts_cannot_authorize_an_archive() {
        let other = digest_key(&object(b"different archive"));
        let object = object(b"archive whose exact receipt is required");
        let manifest = manifest(vec![output(
            b"libarchive.rlib",
            &object,
            OutputRole::Materializable,
        )]);
        let subject = digest_key(&object);
        for (kind, receipt_subject, sequence, decision, reason) in [
            (
                "native-rlib-closure-v0",
                subject.as_str(),
                0,
                RECEIPT_DECISION,
                NATIVE_ARCHIVE_CLOSURE_CONTRACT,
            ),
            (
                "native-rlib-closure-v2",
                subject.as_str(),
                0,
                RECEIPT_DECISION,
                NATIVE_ARCHIVE_CLOSURE_CONTRACT,
            ),
            (
                RECEIPT_KIND,
                other.as_str(),
                0,
                RECEIPT_DECISION,
                NATIVE_ARCHIVE_CLOSURE_CONTRACT,
            ),
            (
                RECEIPT_KIND,
                subject.as_str(),
                1,
                RECEIPT_DECISION,
                NATIVE_ARCHIVE_CLOSURE_CONTRACT,
            ),
            (
                RECEIPT_KIND,
                subject.as_str(),
                0,
                "compiler-succeeded",
                NATIVE_ARCHIVE_CLOSURE_CONTRACT,
            ),
            (RECEIPT_KIND, subject.as_str(), 0, RECEIPT_DECISION, ""),
            (
                RECEIPT_KIND,
                subject.as_str(),
                0,
                RECEIPT_DECISION,
                "some-older-archive-validator",
            ),
        ] {
            let mut store = store();
            store
                .record_decision_receipt(kind, receipt_subject, sequence, decision, reason)
                .unwrap();
            assert!(
                require_manifest(&mut store, &manifest).is_err(),
                "receipt {kind}/{receipt_subject}/{sequence}/{decision}/{reason}"
            );
        }
    }

    #[test]
    fn corrupted_sqlite_field_types_or_oversized_values_cannot_supply_evidence() {
        let object = object(b"archive with a damaged metadata receipt");
        let manifest = manifest(vec![output(
            b"libdamaged.rlib",
            &object,
            OutputRole::Materializable,
        )]);
        for (column, corrupted) in [
            ("kind", SqlValue::Blob(RECEIPT_KIND.as_bytes().to_vec())),
            ("subject", SqlValue::Blob(digest_key(&object).into_bytes())),
            ("seq", SqlValue::Blob(vec![0])),
            (
                "decision",
                SqlValue::Blob(RECEIPT_DECISION.as_bytes().to_vec()),
            ),
            (
                "reason",
                SqlValue::Blob(NATIVE_ARCHIVE_CLOSURE_CONTRACT.as_bytes().to_vec()),
            ),
            ("reason", SqlValue::Text("damaged receipt".repeat(8192))),
        ] {
            let root = tempfile::tempdir().unwrap();
            let database = root.path().join("damaged-closure.sqlite");
            {
                let mut store =
                    SqlMetadataStore::open(RusqliteEngine::open(&database).unwrap()).unwrap();
                record_validated(&mut store, &object).unwrap();
            }
            let mut engine = RusqliteEngine::open(&database).unwrap();
            engine
                .execute(
                    &format!("UPDATE decision_receipts SET {column} = ?1 WHERE kind = ?2"),
                    &[corrupted, SqlValue::Text(RECEIPT_KIND.into())],
                )
                .unwrap();
            let mut reopened = SqlMetadataStore::open(engine).unwrap();
            assert!(
                require_manifest(&mut reopened, &manifest).is_err(),
                "corrupted {column} cannot authorize replay"
            );
        }
    }

    #[test]
    fn conflicting_receipt_is_not_repaired_into_authority() {
        let mut store = store();
        let object = object(b"archive with a conflicting receipt");
        store
            .record_decision_receipt(
                RECEIPT_KIND,
                &digest_key(&object),
                RECEIPT_SEQUENCE,
                "unclosed",
                NATIVE_ARCHIVE_CLOSURE_CONTRACT,
            )
            .unwrap();
        assert!(record_validated(&mut store, &object).is_err());
        assert!(
            require_manifest(
                &mut store,
                &manifest(vec![output(
                    b"libconflicting.rlib",
                    &object,
                    OutputRole::Materializable,
                )]),
            )
            .is_err()
        );
    }

    #[test]
    fn action_or_foreign_domain_digests_cannot_masquerade_as_archive_objects() {
        let mut store = store();
        let original = object(b"validated object bytes");
        record_validated(&mut store, &original).unwrap();
        for domain in [
            rabs_key::typed_digest::DOMAIN_ACTION_KEY,
            "rabs.object.sha256.v0",
            "rabs.object.sha256.v2",
            "rabs.object.v1",
        ] {
            let mut wrong = original.clone();
            wrong.domain = domain;
            assert!(record_validated(&mut store, &wrong).is_err());
            assert!(
                require_manifest(
                    &mut store,
                    &manifest(vec![output(
                        b"libwrong.rlib",
                        &wrong,
                        OutputRole::Materializable,
                    )]),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn metadata_only_results_do_not_require_archive_receipts() {
        let mut store = store();
        let metadata = object(b"metadata bytes");
        let dep_info = object(b"dep-info bytes");
        require_manifest(
            &mut store,
            &manifest(vec![
                output(
                    b"libmetadata.rlib.rmeta",
                    &metadata,
                    OutputRole::ProvisionalMetadata,
                ),
                output(b"libmetadata.d", &dep_info, OutputRole::DepInfo),
            ]),
        )
        .unwrap();
        require_manifest(&mut store, &manifest(Vec::new())).unwrap();
    }

    #[test]
    fn receipt_survives_metadata_store_restart() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("native-closure.sqlite");
        let object = object(b"archive validated before the daemon restart");
        let manifest = manifest(vec![output(
            b"libpersistent.rlib",
            &object,
            OutputRole::Materializable,
        )]);
        {
            let mut store =
                SqlMetadataStore::open(RusqliteEngine::open(&database).unwrap()).unwrap();
            record_validated(&mut store, &object).unwrap();
        }
        let mut reopened =
            SqlMetadataStore::open(RusqliteEngine::open(&database).unwrap()).unwrap();
        require_manifest(&mut reopened, &manifest).unwrap();
    }
}
