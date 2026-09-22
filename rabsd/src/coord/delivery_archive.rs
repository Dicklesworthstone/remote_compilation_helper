//! Content-addressed retention of verified worker deliveries, NOT action reuse.
//!
//! Archive only after the receiver's complete delivery frontier. Store each file
//! through the existing verified/full-durability CAS put, then the receipt/index,
//! reachability edges, and finally an unexpiring retention pin. No action entry,
//! execution lease, serving state, or publication authority is created here.
//! Restore verifies into a private staging tree and runs the ordinary delivery
//! recovery verifier before exposing delivery.json. Failures never execute work.

use super::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use super::worker_delivery::{
    Delivery, MAX_DELIVERY_BYTES, create_artifact_directories, validate_request,
    verified_artifact_names,
};
use crate::janitor::store::LiveCas;
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, RAW_PROFILE_V1, put_if_absent};
use rabs_cas::digest_set::{
    ATP_OBJECT_CONTENT_DOMAIN, DigestRequest, DigestSet, StreamingObjectWriter, digest_set,
};
use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue, digest_key};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path};

const KIND: &str = "rabs.worker-delivery-archive.v1";
const PIN_CLASS: &str = "delivery-archive";
const PIN_OWNER: &str = "rabs-delivery-archive";
const MAX_INDEX_BYTES: u64 = 2 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn failure(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn text<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field))
}
fn number(value: &Value, field: &str) -> io::Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(field))
}

/// Re-type only this build's native content identity, never a wire-supplied domain.
pub fn parse_archive_key(key: &str) -> Result<TypedDigest, String> {
    let body = key
        .strip_prefix(ATP_OBJECT_CONTENT_DOMAIN)
        .and_then(|s| s.strip_prefix(':'))
        .ok_or_else(|| "archive key must be a native CAS content digest".to_owned())?;
    if body.len() != 64
        || !body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("archive key must contain 64 lowercase hex digits".to_owned());
    }
    let mut bytes = [0; 32];
    for (slot, pair) in bytes.iter_mut().zip(body.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *slot = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: ATP_OBJECT_CONTENT_DOMAIN,
        bytes,
    })
}

/// The durable root is a delivery archive, not a canonical action-result manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedDelivery {
    pub root: TypedDigest,
    pub pin: u128,
    pub file_count: usize,
    pub total_bytes: u64,
}
impl ArchivedDelivery {
    pub fn to_json(&self) -> Value {
        json!({"kind":"archived-worker-delivery", "root":digest_key(&self.root),
            "pin":format!("{:032x}",self.pin), "files":self.file_count,
            "total_bytes":self.total_bytes, "publication_authorized":false, "reexecute":false})
    }
}

struct Item {
    len: u64,
    raw_sha256: String,
    executable: bool,
}

/// The live manifest validator constrains the complete archived file set to
/// the original request. Tree requests retain ALL accepted outputs, not only
/// their minimum required names. Recovery checks bytes and provenance again.
fn items(request: &Value, receipt: &Value) -> io::Result<BTreeMap<String, Item>> {
    validate_request(request)?;
    let mut entries = BTreeMap::new();
    for stream in ["stdout", "stderr"] {
        entries.insert(
            format!("diagnostics/{stream}"),
            Item {
                len: number(receipt, &format!("{stream}_bytes"))?,
                raw_sha256: text(receipt, &format!("{stream}_sha256"))?.to_owned(),
                executable: false,
            },
        );
    }
    if receipt.get("exit_code").and_then(Value::as_i64) == Some(0)
        && receipt.get("stop_reason") == Some(&Value::Null)
        && request.get("artifacts").is_some()
    {
        let names = verified_artifact_names(request, &receipt["artifact_manifest"])?;
        let rows = receipt["artifact_manifest"]["files"]
            .as_array()
            .ok_or_else(|| invalid("artifact manifest"))?;
        require(rows.len() == names.len(), "artifact set mismatch")?;
        for (row, name) in rows.iter().zip(names) {
            require(
                text(row, "name")? == name,
                "artifact order or name mismatch",
            )?;
            entries.insert(
                format!("artifacts/{name}"),
                Item {
                    len: number(row, "bytes")?,
                    raw_sha256: text(row, "sha256")?.to_owned(),
                    executable: row
                        .get("executable")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| invalid("artifact executable bit"))?,
                },
            );
        }
    }
    let mut total = 0_u64;
    for item in entries.values() {
        require(
            item.raw_sha256.len() == 64
                && item
                    .raw_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid raw digest",
        )?;
        total = total
            .checked_add(item.len)
            .ok_or_else(|| invalid("delivery length overflow"))?;
        require(total <= MAX_DELIVERY_BYTES, "delivery budget exceeded")?;
    }
    require(
        total == number(receipt, "total_bytes")?,
        "delivery total mismatch",
    )?;
    Ok(entries)
}

fn not_quarantined(store: &mut dyn RabsMetadataStore, object: &TypedDigest) -> io::Result<()> {
    let rows = store
        .query(
            "SELECT 1 FROM quarantines WHERE scope = 'logical-object' AND subject = ?1 LIMIT 1",
            &[SqlValue::Text(digest_key(object))],
        )
        .map_err(failure)?;
    require(rows.is_empty(), "logical CAS object is quarantined")
}

fn stream(reader: &mut dyn Read, sink: &mut dyn Write, limit: u64) -> io::Result<DigestSet> {
    let mut writer = StreamingObjectWriter::new(
        DigestRequest {
            blake3: false,
            raw_sha256: true,
        },
        None,
    );
    let mut total = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("byte count overflow"))?;
        require(total <= limit, "CAS copy exceeds its byte budget")?;
        writer.write(&buffer[..count]).map_err(failure)?;
        sink.write_all(&buffer[..count])?;
    }
    writer.finish().map_err(failure)
}

fn matches_item(digests: &DigestSet, item: &Item) -> bool {
    digests.logical_size == item.len
        && digests
            .raw_sha256
            .is_some_and(|raw| hex(&raw.0) == item.raw_sha256)
}

fn ordinary_file(path: &Path) -> io::Result<File> {
    require(
        fs::symlink_metadata(path)?.is_file(),
        "CAS/delivery source is not an ordinary file",
    )?;
    let file = File::open(path)?;
    require(
        file.metadata()?.is_file(),
        "CAS/delivery source changed type",
    )?;
    Ok(file)
}

/// Find a byte-verified durable raw replica. Corrupt replicas remain on disk as
/// evidence but are durably quarantined; a valid second replica may satisfy it.
fn open_object(
    store: &mut dyn RabsMetadataStore,
    object: &TypedDigest,
    limit: u64,
) -> io::Result<(File, String)> {
    not_quarantined(store, object)?;
    for (path, encoding, durable) in store.object_locations(object).map_err(failure)? {
        if encoding != RAW_PROFILE_V1 || !durable {
            continue;
        }
        let Ok(mut file) = ordinary_file(Path::new(&path)) else {
            continue;
        };
        if file.metadata()?.len() > limit {
            continue;
        }
        let digests = match stream(&mut file, &mut io::sink(), limit) {
            Ok(digests) => digests,
            Err(_) => continue,
        };
        if digests.atp_content_id != *object {
            store
                .set_location_quarantined(object, &path, true)
                .map_err(failure)?;
            continue;
        }
        file.rewind()?;
        return Ok((file, path));
    }
    Err(invalid("no byte-verified durable raw CAS replica"))
}

fn pin_id(root: &TypedDigest) -> u128 {
    let mut h = Sha256::new();
    h.update(b"rabs.delivery-archive.pin.v1");
    h.update(root.bytes);
    let hash = h.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    u128::from_be_bytes(bytes)
}
fn check_pin(store: &mut dyn RabsMetadataStore, root: &TypedDigest) -> io::Result<bool> {
    match store.pin_row(pin_id(root)).map_err(failure)? {
        None => Ok(false),
        Some(pin) => {
            require(
                pin.root_key == digest_key(root)
                    && pin.owner == PIN_OWNER
                    && pin.class == PIN_CLASS
                    && !pin.released
                    && pin.expires_at_seq.is_none(),
                "archive pin collision, release or policy mismatch",
            )?;
            Ok(true)
        }
    }
}

/// Import verified bytes into the real CAS with one durable retention root.
/// Hold the metadata mutex through puts/edges/pin so the janitor cannot reclaim
/// an in-progress closure. The mount lock excludes other production processes.
/// A crash before the final pin leaves only unreferenced blobs, never an action
/// publication. The original delivery is read-only and is never discarded.
pub fn archive_delivery(
    cas: &LiveCas,
    request: &Value,
    worker: &str,
    source: &Path,
    trust: DeliveryTrust,
) -> Result<ArchivedDelivery, String> {
    let result = (|| -> io::Result<ArchivedDelivery> {
        require(
            !cas.serving_refused,
            "CAS startup reconciliation refused the store",
        )?;
        let delivery = recover_existing_delivery(request, worker, source, trust)
            .map_err(|e| io::Error::other(e.to_string()))?
            .ok_or_else(|| invalid("verified delivery is absent; no execution is attempted"))?;
        let plan = items(request, &delivery.receipt)?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| invalid("CAS metadata lock poisoned"))?;
        store.intern_domain(ATP_OBJECT_CONTENT_DOMAIN);
        let mut objects = Vec::new();
        let mut children = Vec::new();
        for (path, item) in &plan {
            let mut file = ordinary_file(&source.join(path))?;
            let digests = stream(&mut file, &mut io::sink(), item.len)?;
            require(
                matches_item(&digests, item),
                "delivery changed since verification",
            )?;
            let object = digests.atp_content_id;
            not_quarantined(&mut *store, &object)?;
            file.rewind()?;
            // put_if_absent independently rehashes the exact stored bytes. A
            // source edit between passes cannot attach the earlier identity.
            put_if_absent(
                cas.layout(),
                &mut *store,
                &object,
                &mut file,
                PutLimits {
                    max_logical_bytes: Some(item.len),
                    expected_size: Some(item.len),
                },
                DurabilityPolicy::FULL,
            )
            .map_err(failure)?;
            objects.push(json!([path, digest_key(&object)]));
            children.push(object);
        }
        let index = json!({"version":1,"kind":KIND,"receipt":delivery.receipt,"objects":objects});
        let bytes = serde_json::to_vec(&index)?;
        require(
            bytes.len() as u64 <= MAX_INDEX_BYTES,
            "archive index exceeds its budget",
        )?;
        let root = digest_set(&bytes, DigestRequest::default(), None)
            .map_err(failure)?
            .atp_content_id;
        not_quarantined(&mut *store, &root)?;
        let already_pinned = check_pin(&mut *store, &root)?;
        put_if_absent(
            cas.layout(),
            &mut *store,
            &root,
            &mut bytes.as_slice(),
            PutLimits {
                max_logical_bytes: Some(MAX_INDEX_BYTES),
                expected_size: Some(bytes.len() as u64),
            },
            DurabilityPolicy::FULL,
        )
        .map_err(failure)?;
        for child in &children {
            store
                .add_object_edge(&root, child, "delivery-file")
                .map_err(failure)?;
        }
        store
            .record_manifest(&root, KIND, plan.len() as u64)
            .map_err(failure)?;
        if !already_pinned {
            store
                .create_pin(
                    pin_id(&root),
                    &root,
                    PIN_OWNER,
                    PIN_CLASS,
                    None,
                    None,
                    true,
                    "verified delivery retention; no action publication",
                )
                .map_err(failure)?;
        }
        Ok(ArchivedDelivery {
            pin: pin_id(&root),
            root,
            file_count: plan.len(),
            total_bytes: number(&index["receipt"], "total_bytes")?,
        })
    })();
    result.map_err(|error| format!("delivery archive failed without executing work: {error}"))
}

fn mkdir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn sync_dirs(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_dirs(&entry.path())?;
        }
    }
    File::open(root)?.sync_all()
}

/// Restore the exact archived delivery to a new or already-complete directory. This is not a cache
/// lookup: the original request and historical trust policy are mandatory. No
/// source delivery, worker connection, or compiler is needed. Failed staging is
/// retained, never reused; an existing destination is never overwritten. A
/// complete matching restore is verified and returned idempotently.
pub fn restore_delivery(
    cas: &LiveCas,
    root_key: &str,
    request: &Value,
    worker: &str,
    destination: &Path,
    trust: DeliveryTrust,
) -> Result<Delivery, String> {
    let result = (|| -> io::Result<Delivery> {
        validate_request(request)?;
        require(
            !cas.serving_refused,
            "CAS startup reconciliation refused the store",
        )?;
        require(
            destination.is_absolute()
                && destination
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "invalid restore destination",
        )?;
        let root = parse_archive_key(root_key).map_err(io::Error::other)?;
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| invalid("CAS metadata lock poisoned"))?;
        store.intern_domain(ATP_OBJECT_CONTENT_DOMAIN);
        require(
            check_pin(&mut *store, &root)?,
            "archive has no active retention pin",
        )?;
        let (mut file, _) = open_object(&mut *store, &root, MAX_INDEX_BYTES)?;
        let mut bytes = Vec::new();
        let digests = stream(&mut file, &mut bytes, MAX_INDEX_BYTES)?;
        require(
            digests.atp_content_id == root,
            "archive index changed while reading",
        )?;
        let index: Value = serde_json::from_slice(&bytes)?;
        require(
            index.as_object().is_some_and(|map| map.len() == 4)
                && number(&index, "version")? == 1
                && text(&index, "kind")? == KIND,
            "unsupported archive index",
        )?;
        let receipt = &index["receipt"];
        require(
            text(receipt, "worker_id")? == worker
                && number(receipt, "request_id")? == number(request, "request_id")?
                && text(receipt, "request_sha256")?
                    == hex(&Sha256::digest(serde_json::to_vec(request)?)),
            "archive belongs to a different worker or request",
        )?;
        let plan = items(request, &index["receipt"])?;
        let references = index["objects"]
            .as_array()
            .ok_or_else(|| invalid("archive object list"))?;
        require(
            references.len() == plan.len(),
            "archive object set mismatch",
        )?;
        let mut objects = Vec::new();
        for (entry, (path, _)) in references.iter().zip(&plan) {
            let pair = entry
                .as_array()
                .ok_or_else(|| invalid("archive object entry"))?;
            require(
                pair.len() == 2 && pair[0].as_str() == Some(path.as_str()),
                "archive path/order mismatch",
            )?;
            let object =
                parse_archive_key(pair[1].as_str().ok_or_else(|| invalid("object digest"))?)
                    .map_err(io::Error::other)?;
            objects.push(object);
        }
        require(
            store.manifest_meta(&root).map_err(failure)?
                == Some((KIND.to_owned(), plan.len() as u64)),
            "archive metadata mismatch",
        )?;
        for object in &objects {
            not_quarantined(&mut *store, object)?;
        }
        if let Some(mut existing) = recover_existing_delivery(request, worker, destination, trust)
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            require(
                existing.receipt == index["receipt"],
                "existing delivery belongs to a different archive result",
            )?;
            // The request alone is not a result identity: two nondeterministic
            // executions may share it. Also verify each native CAS identity,
            // rather than trusting only the receipt's raw content hashes.
            for ((path, item), object) in plan.iter().zip(&objects) {
                let mut file = ordinary_file(&destination.join(path))?;
                let digests = stream(&mut file, &mut io::sink(), item.len)?;
                require(
                    digests.atp_content_id == *object && matches_item(&digests, item),
                    "existing delivery differs from this archive's object map",
                )?;
            }
            existing.acknowledgment_error = Some(
                "verified an existing CAS restore; remote acknowledgments were not rechecked"
                    .to_owned(),
            );
            return Ok(existing);
        }
        // Only private staging is populated until the ordinary recovery verifier
        // checks receipt/request/provenance, the exact tree, modes and raw hashes.
        mkdir(destination)?;
        let staging = destination.join(".restore-staging");
        mkdir(&staging)?;
        mkdir(&staging.join("diagnostics"))?;
        mkdir(&staging.join("artifacts"))?;
        create_artifact_directories(
            &staging.join("artifacts"),
            plan.keys().filter_map(|path| path.strip_prefix("artifacts/")),
        )?;
        for ((path, item), object) in plan.iter().zip(&objects) {
            let target = staging.join(path);
            let (mut source, location) = open_object(&mut *store, object, item.len)?;
            let mut output = create_file(&target)?;
            let digests = stream(&mut source, &mut output, item.len)?;
            if digests.atp_content_id != *object {
                store
                    .set_location_quarantined(object, &location, true)
                    .map_err(failure)?;
                return Err(invalid("CAS replica changed during restore"));
            }
            require(
                matches_item(&digests, item),
                "archive object differs from delivery receipt",
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                output.set_permissions(fs::Permissions::from_mode(if item.executable {
                    0o700
                } else {
                    0o600
                }))?;
            }
            output.sync_all()?;
        }
        let mut marker = create_file(&staging.join("delivery.json"))?;
        marker.write_all(&serde_json::to_vec(&index["receipt"])?)?;
        marker.sync_all()?;
        drop(marker);
        sync_dirs(&staging)?;
        let verified = recover_existing_delivery(request, worker, &staging, trust)
            .map_err(|e| io::Error::other(e.to_string()))?
            .ok_or_else(|| invalid("restored staging disappeared"))?;
        fs::rename(staging.join("diagnostics"), destination.join("diagnostics"))?;
        fs::rename(staging.join("artifacts"), destination.join("artifacts"))?;
        fs::rename(
            staging.join("delivery.json"),
            destination.join("delivery.pending"),
        )?;
        // Remove only our now-empty staging directory, never source deliveries,
        // existing destinations, or a failed partial restore.
        fs::remove_dir(&staging)?;
        sync_dirs(destination)?;
        for parent in destination.ancestors().skip(1) {
            File::open(parent)?.sync_all()?;
        }
        fs::rename(
            destination.join("delivery.pending"),
            destination.join("delivery.json"),
        )?;
        File::open(destination)?.sync_all()?;
        Ok(Delivery {
            directory: destination.to_path_buf(),
            receipt: verified.receipt,
            acknowledgments_confirmed: false,
            acknowledgment_error: Some(
                "restored from CAS; remote acknowledgments were not rechecked".to_owned(),
            ),
        })
    })();
    result.map_err(|error| {
        format!("archive restore refused; no execution or retry was attempted: {error}")
    })
}
