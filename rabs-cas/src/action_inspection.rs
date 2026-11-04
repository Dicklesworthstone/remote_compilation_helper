//! Bounded, read-only inspection of the facts recorded for one action.
//!
//! This path deliberately does not construct `SqlMetadataStore`: opening that
//! store applies migrations. An inspector must neither create a missing CAS nor
//! upgrade one owned by a running coordinator. All sections come from one SQLite
//! read transaction, including when the coordinator is writing in WAL mode.
//!
//! These are recorded facts, not a serving authorization. In particular, a
//! publication survives quarantine, and a stored `servable` disposition does not
//! evaluate the coordinator's current clock, authority, or class-wide gates.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Row, Transaction, TransactionBehavior};

use crate::metadata_store::SCHEMA_VERSION;

const ACTION_DOMAIN: &str = "rabs.action-key.sha256.v1";
const MAX_TEXT_BYTES: usize = 4096;

/// Maximum number of rows returned in each per-action list.
pub const INSPECTION_ROW_LIMIT: usize = 64;

/// A bounded list; truncation means that additional recorded rows exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionRows<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

/// One consistent snapshot of the locally recorded facts for an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionInspection {
    pub action_key: String,
    pub schema_version: u32,
    /// At least one of the inspected tables has a record for this action.
    pub observed: bool,
    pub entry: Option<ActionEntryInspection>,
    pub publication: Option<PublicationInspection>,
    pub serving: Option<ServingInspection>,
    /// Latest versioned evaluation written by the live coordinator.
    pub trust_evaluation: Option<TrustEvaluationInspection>,
    /// Older mutable trust metadata, retained separately when present.
    pub legacy_trust: Option<TrustInspection>,
    pub runtime_class: Option<String>,
    pub action_quarantine: Option<String>,
    /// Incidents currently have no verified resolution API. Their presence is
    /// independently blocking, even if a later serving record says `servable`.
    pub has_unresolved_divergence: bool,
    pub blocking_quarantines: InspectionRows<QuarantineInspection>,
    /// Empty means no components were recorded, not that two keys are equal.
    pub breakdown: InspectionRows<BreakdownInspection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEntryInspection {
    pub key_epoch: u32,
    pub projection_epoch: u32,
}

/// A committed publication, irrespective of whether it is currently usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationInspection {
    pub descriptor: String,
    pub manifest: String,
    pub winner_generation: String,
    pub winner_attempt: String,
    pub winner_worker: Option<String>,
    pub result_kind: String,
    pub pin_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingInspection {
    pub disposition: String,
    pub version: u32,
    pub state_revision: u64,
    pub authority_key: String,
    pub evaluated_at_micros: i64,
    pub max_age_micros: Option<u64>,
    pub clock_uncertainty_micros: u64,
    pub clock_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustInspection {
    pub state: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEvaluationInspection {
    pub version: u32,
    pub state: String,
    pub reason: String,
    pub evaluated_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineInspection {
    pub scope: String,
    pub subject: String,
    /// `None` preserves a dangling blocking reference instead of hiding it.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakdownInspection {
    pub component: String,
    pub algorithm: String,
    pub domain: String,
    pub digest_hex: String,
}

#[derive(Debug)]
pub enum InspectionError {
    InvalidActionKey,
    UnsupportedSchema { expected: u32, found: Option<i64> },
    InvalidMetadata(String),
    Database(rusqlite::Error),
}

impl fmt::Display for InspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidActionKey => write!(
                f,
                "expected 64 hexadecimal action-key digits or {ACTION_DOMAIN}: followed by those digits"
            ),
            Self::UnsupportedSchema { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "CAS metadata schema {found} is unsupported; expected {expected}; inspection does not run migrations"
                ),
                None => write!(
                    f,
                    "CAS metadata has no schema version; expected {expected}; inspection does not initialize a store"
                ),
            },
            Self::InvalidMetadata(detail) => write!(f, "invalid CAS metadata: {detail}"),
            Self::Database(error) => write!(f, "cannot inspect CAS metadata: {error}"),
        }
    }
}

impl std::error::Error for InspectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for InspectionError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

/// Inspect an existing `meta.sqlite` without creating or migrating it.
///
/// Accepts a bare 64-digit digest or the canonical action-key domain followed by
/// that digest. Hexadecimal digits are normalized to lowercase. The database is
/// opened read-only, with bounded lock waiting and without SQLite's `immutable`
/// option: an active coordinator's WAL must remain visible.
pub fn inspect_action(database: &Path, key: &str) -> Result<ActionInspection, InspectionError> {
    let key = normalize_key(key)?;
    let mut connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_millis(250))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let version = inspect_schema(&transaction)?;
    let inspection = inspect_snapshot(&transaction, key, version)?;
    transaction.commit()?;
    Ok(inspection)
}

fn normalize_key(key: &str) -> Result<String, InspectionError> {
    let hex = key
        .strip_prefix(ACTION_DOMAIN)
        .and_then(|suffix| suffix.strip_prefix(':'))
        .unwrap_or(key);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(InspectionError::InvalidActionKey);
    }
    Ok(format!("{ACTION_DOMAIN}:{}", hex.to_ascii_lowercase()))
}

fn inspect_schema(transaction: &Transaction<'_>) -> Result<u32, InspectionError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_epochs')",
        [],
        |row| row.get(0),
    )?;
    let found = if exists {
        optional_row(
            transaction,
            "SELECT version FROM schema_epochs ORDER BY version DESC LIMIT 1",
            None,
            |row| integer(row, 0, "schema version"),
        )?
    } else {
        None
    };
    if found != Some(i64::from(SCHEMA_VERSION)) {
        return Err(InspectionError::UnsupportedSchema {
            expected: SCHEMA_VERSION,
            found,
        });
    }
    Ok(SCHEMA_VERSION)
}

fn inspect_snapshot(
    transaction: &Transaction<'_>,
    action_key: String,
    schema_version: u32,
) -> Result<ActionInspection, InspectionError> {
    let entry = optional_row(
        transaction,
        "SELECT algo, domain, bytes, key_epoch, projection_epoch FROM action_entries WHERE key = ?1",
        Some(&action_key),
        |row| {
            let digest = digest(row, 0)?;
            if format!("{}:{}", digest.domain, digest.digest_hex) != action_key {
                return Err(invalid("action entry digest does not match its key"));
            }
            Ok(ActionEntryInspection {
                key_epoch: unsigned32(row, 3, "key epoch")?,
                projection_epoch: unsigned32(row, 4, "projection epoch")?,
            })
        },
    )?;
    let mut publication = optional_row(
        transaction,
        "SELECT descriptor_algo, descriptor_domain, descriptor_bytes, \
         manifest_algo, manifest_domain, manifest_bytes, winner_generation_hex, \
         winner_attempt_hex, result_kind, pin_hex FROM action_publications WHERE action_key = ?1",
        Some(&action_key),
        |row| {
            let descriptor = digest(row, 0)?;
            let manifest = digest(row, 3)?;
            Ok(PublicationInspection {
                descriptor: format!("{}:{}", descriptor.domain, descriptor.digest_hex),
                manifest: format!("{}:{}", manifest.domain, manifest.digest_hex),
                winner_generation: identifier(row, 6, "winning generation")?,
                winner_attempt: identifier(row, 7, "winning attempt")?,
                winner_worker: None,
                result_kind: text(row, 8, "result kind")?,
                pin_id: identifier(row, 9, "publication pin")?,
            })
        },
    )?;
    if let Some(publication) = &mut publication {
        publication.winner_worker = optional_row(
            transaction,
            "SELECT worker, generation_hex FROM action_attempts WHERE id_hex = ?1",
            Some(&publication.winner_attempt),
            |row| {
                if identifier(row, 1, "attempt generation")? != publication.winner_generation {
                    return Err(invalid("winning attempt belongs to a different generation"));
                }
                text(row, 0, "winning worker")
            },
        )?;
    }
    let serving = optional_row(
        transaction,
        "SELECT disposition, version, state_revision, authority_key, evaluated_at_micros, \
         max_age_micros, clock_uncertainty_micros, clock_epoch \
         FROM action_serving_states WHERE action_key = ?1",
        Some(&action_key),
        |row| {
            Ok(ServingInspection {
                disposition: text(row, 0, "serving disposition")?,
                version: unsigned32(row, 1, "serving version")?,
                state_revision: unsigned(row, 2, "serving revision")?,
                authority_key: text(row, 3, "serving authority")?,
                evaluated_at_micros: integer(row, 4, "evaluation time")?,
                max_age_micros: if matches!(row.get_ref(5)?, ValueRef::Null) {
                    None
                } else {
                    Some(unsigned(row, 5, "maximum age")?)
                },
                clock_uncertainty_micros: unsigned(row, 6, "clock uncertainty")?,
                clock_epoch: unsigned(row, 7, "clock epoch")?,
            })
        },
    )?;
    let trust_evaluation = optional_row(
        transaction,
        "SELECT version, state, reason, evaluated_seq FROM action_trust_evaluations \
         WHERE action_key = ?1 ORDER BY version DESC LIMIT 1",
        Some(&action_key),
        |row| {
            Ok(TrustEvaluationInspection {
                version: unsigned32(row, 0, "trust evaluation version")?,
                state: text(row, 1, "trust evaluation state")?,
                reason: text(row, 2, "trust evaluation reason")?,
                evaluated_seq: unsigned(row, 3, "trust evaluation sequence")?,
            })
        },
    )?;
    let legacy_trust = optional_row(
        transaction,
        "SELECT state, reason FROM trust_states WHERE action_key = ?1",
        Some(&action_key),
        |row| {
            Ok(TrustInspection {
                state: text(row, 0, "trust state")?,
                reason: text(row, 1, "trust reason")?,
            })
        },
    )?;
    let runtime_class = optional_row(
        transaction,
        "SELECT decision FROM decision_receipts \
         WHERE kind = 'rabs-live-action-class-v1' AND subject = ?1 AND seq = 0",
        Some(&action_key),
        |row| text(row, 0, "runtime class"),
    )?;
    let action_quarantine = optional_row(
        transaction,
        "SELECT reason FROM quarantines WHERE scope = 'action-entry' AND subject = ?1",
        Some(&action_key),
        |row| text(row, 0, "action quarantine reason"),
    )?;
    // This is the same per-action existence predicate used by serving_state.
    // It includes observable-only incidents, which may have no quarantine row.
    let has_unresolved_divergence: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM divergence_incidents WHERE action_key = ?1 LIMIT 1)",
        [&action_key],
        |row| row.get(0),
    )?;
    let blocking_quarantines = bounded_rows(
        transaction,
        "SELECT b.scope, b.subject, q.reason FROM serving_blocking_quarantines AS b \
         LEFT JOIN quarantines AS q ON q.scope = b.scope AND q.subject = b.subject \
         WHERE b.action_key = ?1 ORDER BY b.scope, b.subject LIMIT 65",
        &action_key,
        |row| {
            Ok(QuarantineInspection {
                scope: text(row, 0, "blocking quarantine scope")?,
                subject: text(row, 1, "blocking quarantine subject")?,
                reason: if matches!(row.get_ref(2)?, ValueRef::Null) {
                    None
                } else {
                    Some(text(row, 2, "blocking quarantine reason")?)
                },
            })
        },
    )?;
    let breakdown = bounded_rows(
        transaction,
        "SELECT component, algo, domain, bytes FROM key_breakdowns \
         WHERE action_key = ?1 ORDER BY component LIMIT 65",
        &action_key,
        |row| {
            let digest = digest(row, 1)?;
            Ok(BreakdownInspection {
                component: text(row, 0, "key component")?,
                algorithm: digest.algorithm,
                domain: digest.domain,
                digest_hex: digest.digest_hex,
            })
        },
    )?;
    let observed = entry.is_some()
        || publication.is_some()
        || serving.is_some()
        || trust_evaluation.is_some()
        || legacy_trust.is_some()
        || runtime_class.is_some()
        || action_quarantine.is_some()
        || has_unresolved_divergence
        || !blocking_quarantines.items.is_empty()
        || !breakdown.items.is_empty();
    Ok(ActionInspection {
        action_key,
        schema_version,
        observed,
        entry,
        publication,
        serving,
        trust_evaluation,
        legacy_trust,
        runtime_class,
        action_quarantine,
        has_unresolved_divergence,
        blocking_quarantines,
        breakdown,
    })
}

fn optional_row<T>(
    transaction: &Transaction<'_>,
    sql: &str,
    key: Option<&str>,
    decode: impl FnOnce(&Row<'_>) -> Result<T, InspectionError>,
) -> Result<Option<T>, InspectionError> {
    let mut statement = transaction.prepare(sql)?;
    let mut rows = if let Some(key) = key {
        statement.query([key])?
    } else {
        statement.query([])?
    };
    match rows.next()? {
        Some(row) => Ok(Some(decode(row)?)),
        None => Ok(None),
    }
}

fn bounded_rows<T>(
    transaction: &Transaction<'_>,
    sql: &str,
    key: &str,
    decode: impl Fn(&Row<'_>) -> Result<T, InspectionError>,
) -> Result<InspectionRows<T>, InspectionError> {
    let mut statement = transaction.prepare(sql)?;
    let mut rows = statement.query([key])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        if items.len() == INSPECTION_ROW_LIMIT {
            return Ok(InspectionRows {
                items,
                truncated: true,
            });
        }
        items.push(decode(row)?);
    }
    Ok(InspectionRows {
        items,
        truncated: false,
    })
}

fn invalid(detail: impl Into<String>) -> InspectionError {
    InspectionError::InvalidMetadata(detail.into())
}

fn text(row: &Row<'_>, index: usize, field: &str) -> Result<String, InspectionError> {
    match row.get_ref(index)? {
        ValueRef::Text(bytes) if bytes.len() <= MAX_TEXT_BYTES => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| invalid(format!("{field} is not UTF-8"))),
        ValueRef::Text(_) => Err(invalid(format!("{field} exceeds {MAX_TEXT_BYTES} bytes"))),
        _ => Err(invalid(format!("{field} is not text"))),
    }
}

fn integer(row: &Row<'_>, index: usize, field: &str) -> Result<i64, InspectionError> {
    match row.get_ref(index)? {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(invalid(format!("{field} is not an integer"))),
    }
}

fn unsigned(row: &Row<'_>, index: usize, field: &str) -> Result<u64, InspectionError> {
    u64::try_from(integer(row, index, field)?)
        .map_err(|_| invalid(format!("{field} must not be negative")))
}

fn unsigned32(row: &Row<'_>, index: usize, field: &str) -> Result<u32, InspectionError> {
    u32::try_from(unsigned(row, index, field)?)
        .map_err(|_| invalid(format!("{field} is outside the u32 range")))
}

fn identifier(row: &Row<'_>, index: usize, field: &str) -> Result<String, InspectionError> {
    let value = text(row, index, field)?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{field} is not a canonical u128 identifier"
        )));
    }
    Ok(value)
}

struct Digest {
    algorithm: String,
    domain: String,
    digest_hex: String,
}

fn digest(row: &Row<'_>, index: usize) -> Result<Digest, InspectionError> {
    let algorithm = text(row, index, "digest algorithm")?;
    if algorithm != "sha256-v1" {
        return Err(invalid("unsupported digest algorithm"));
    }
    let domain = text(row, index + 1, "digest domain")?;
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(invalid("invalid digest domain"));
    }
    let ValueRef::Blob(bytes) = row.get_ref(index + 2)? else {
        return Err(invalid("digest bytes are not a blob"));
    };
    if bytes.len() != 32 {
        return Err(invalid("digest is not 32 bytes"));
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest_hex = String::with_capacity(64);
    for byte in bytes {
        digest_hex.push(char::from(HEX[usize::from(byte >> 4)]));
        digest_hex.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(Digest {
        algorithm,
        domain,
        digest_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::MIGRATIONS;
    use rusqlite::params;

    fn key() -> String {
        format!("{ACTION_DOMAIN}:{}", "ab".repeat(32))
    }

    fn database() -> (tempfile::TempDir, Connection) {
        let directory = tempfile::tempdir().unwrap();
        let connection = Connection::open(directory.path().join("meta.sqlite")).unwrap();
        for migration in MIGRATIONS {
            for sql in migration.statements {
                connection.execute_batch(sql).unwrap();
            }
            connection
                .execute(
                    "INSERT INTO schema_epochs (version, applied_seq) VALUES (?1, ?1)",
                    [migration.version],
                )
                .unwrap();
        }
        (directory, connection)
    }

    fn inspect(directory: &tempfile::TempDir) -> ActionInspection {
        inspect_action(&directory.path().join("meta.sqlite"), &key()).unwrap()
    }

    fn insert_entry(connection: &Connection) {
        connection
            .execute(
                "INSERT INTO action_entries VALUES (?1, 'sha256-v1', ?2, ?3, 3, 4)",
                params![key(), ACTION_DOMAIN, [0xab_u8; 32].as_slice()],
            )
            .unwrap();
    }

    fn insert_publication(connection: &Connection) {
        connection
            .execute(
                "INSERT INTO action_publications VALUES \
                 (?1, 'sha256-v1', 'rabs.action-descriptor.sha256.v1', ?2, \
                 'sha256-v1', 'rabs.manifest.sha256.v1', ?3, ?4, ?5, 'success', ?6)",
                params![
                    key(),
                    [1_u8; 32].as_slice(),
                    [2_u8; 32].as_slice(),
                    format!("{:032x}", 1),
                    format!("{:032x}", 2),
                    format!("{:032x}", 3),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO action_attempts (id_hex, id, generation_hex, worker, seq) \
                 VALUES (?1, ?2, ?3, 'worker-east', 1)",
                params![
                    format!("{:032x}", 2),
                    2_u128.to_be_bytes().as_slice(),
                    format!("{:032x}", 1),
                ],
            )
            .unwrap();
    }

    #[test]
    fn missing_database_is_not_created_and_invalid_key_precedes_open() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.sqlite");
        assert!(matches!(
            inspect_action(&missing, "bad-key"),
            Err(InspectionError::InvalidActionKey)
        ));
        assert!(matches!(
            inspect_action(&missing, &key()),
            Err(InspectionError::Database(_))
        ));
        assert!(!missing.exists());
    }

    #[test]
    fn accepts_only_action_domain_and_exact_hex_and_normalizes_case() {
        let (directory, _) = database();
        insert_entry(&Connection::open(directory.path().join("meta.sqlite")).unwrap());
        let inspection =
            inspect_action(&directory.path().join("meta.sqlite"), &"AB".repeat(32)).unwrap();
        assert_eq!(inspection.action_key, key());
        assert!(inspection.entry.is_some());
        for invalid in [
            format!("rabs.object.sha256.v1:{}", "ab".repeat(32)),
            format!("{} ", key()),
            format!(" {}", key()),
            "ab".repeat(31),
            "gg".repeat(32),
            format!("{}:extra", key()),
        ] {
            assert!(matches!(
                inspect_action(&directory.path().join("meta.sqlite"), &invalid),
                Err(InspectionError::InvalidActionKey)
            ));
        }
    }

    #[test]
    fn schema_mismatch_and_uninitialized_database_are_never_migrated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("meta.sqlite");
        let connection = Connection::open(&path).unwrap();
        assert!(matches!(
            inspect_action(&path, &key()),
            Err(InspectionError::UnsupportedSchema { found: None, .. })
        ));
        connection
            .execute_batch("CREATE TABLE schema_epochs (version INTEGER PRIMARY KEY, applied_seq INTEGER NOT NULL)")
            .unwrap();
        for version in [1, i64::from(SCHEMA_VERSION) + 1] {
            connection.execute("DELETE FROM schema_epochs", []).unwrap();
            connection
                .execute("INSERT INTO schema_epochs VALUES (?1, 0)", [version])
                .unwrap();
            let before = std::fs::read(&path).unwrap();
            assert!(matches!(
                inspect_action(&path, &key()),
                Err(InspectionError::UnsupportedSchema { found: Some(found), .. }) if found == version
            ));
            assert_eq!(before, std::fs::read(&path).unwrap());
            let tables: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE type = 'table'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(tables, 1);
        }
    }

    #[test]
    fn unknown_action_and_receipt_without_entry_are_distinct() {
        let (directory, connection) = database();
        let unknown = inspect(&directory);
        assert!(!unknown.observed);
        assert!(unknown.entry.is_none());
        assert!(unknown.breakdown.items.is_empty());
        assert!(!unknown.breakdown.truncated);
        connection
            .execute(
                "INSERT INTO decision_receipts VALUES (?1, ?2, 0, 'rustc-test-class', 'descriptor class')",
                params!["rabs-live-action-class-v1", key()],
            )
            .unwrap();
        let admitted = inspect(&directory);
        assert!(admitted.observed);
        assert!(admitted.entry.is_none());
        assert_eq!(admitted.runtime_class.as_deref(), Some("rustc-test-class"));
    }

    #[test]
    fn ledger_only_action_is_observed_and_uses_latest_version() {
        let (directory, connection) = database();
        for (version, sequence) in [(1, 100), (3, 300), (2, 400)] {
            connection
                .execute(
                    "INSERT INTO action_trust_evaluations VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        key(),
                        version,
                        format!("state-{version}"),
                        format!("reason-{version}"),
                        sequence,
                    ],
                )
                .unwrap();
        }
        let inspection = inspect(&directory);
        assert!(inspection.observed);
        assert!(inspection.entry.is_none());
        assert!(inspection.legacy_trust.is_none());
        assert_eq!(
            inspection.trust_evaluation,
            Some(TrustEvaluationInspection {
                version: 3,
                state: "state-3".into(),
                reason: "reason-3".into(),
                evaluated_seq: 300,
            })
        );
    }

    #[test]
    fn live_evaluation_is_separate_from_stale_legacy_trust() {
        let (directory, connection) = database();
        connection
            .execute(
                "INSERT INTO trust_states VALUES (?1, 'legacy-accepted', 'old mutable state')",
                [key()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO action_trust_evaluations VALUES (?1, 7, 'live-refused', 'new evaluation', 99)",
                [key()],
            )
            .unwrap();
        let inspection = inspect(&directory);
        assert_eq!(inspection.trust_evaluation.unwrap().state, "live-refused");
        assert_eq!(inspection.legacy_trust.unwrap().state, "legacy-accepted");
    }

    #[test]
    fn publication_survives_recorded_blocking_and_dangling_quarantine() {
        let (directory, connection) = database();
        insert_entry(&connection);
        insert_publication(&connection);
        connection
            .execute(
                "INSERT INTO action_serving_states \
                 (action_key, disposition, version, state_revision, authority_key, \
                 evaluated_at_micros, max_age_micros, clock_uncertainty_micros, clock_epoch) \
                 VALUES (?1, 'quarantined', 7, 8, 'authority-one', 100, 500, 3, 9)",
                [key()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO trust_states VALUES (?1, 'refused', 'comparison failed')",
                [key()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO quarantines VALUES ('action-entry', ?1, 'canonical divergence')",
                [key()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO serving_blocking_quarantines VALUES (?1, 'action-entry', ?1), \
                 (?1, 'object', 'missing-referenced-object')",
                [key()],
            )
            .unwrap();
        let before = std::fs::read(directory.path().join("meta.sqlite")).unwrap();
        let inspection = inspect(&directory);
        assert_eq!(
            before,
            std::fs::read(directory.path().join("meta.sqlite")).unwrap()
        );
        assert_eq!(inspection.entry.unwrap().key_epoch, 3);
        let publication = inspection.publication.unwrap();
        assert_eq!(publication.result_kind, "success");
        assert_eq!(publication.winner_worker.as_deref(), Some("worker-east"));
        assert_eq!(publication.winner_generation, format!("{:032x}", 1));
        assert_eq!(publication.winner_attempt, format!("{:032x}", 2));
        assert_eq!(publication.pin_id, format!("{:032x}", 3));
        assert_eq!(
            publication.manifest,
            format!("rabs.manifest.sha256.v1:{}", "02".repeat(32))
        );
        let serving = inspection.serving.unwrap();
        assert_eq!(serving.disposition, "quarantined");
        assert_eq!(serving.version, 7);
        assert_eq!(serving.state_revision, 8);
        assert_eq!(serving.max_age_micros, Some(500));
        assert_eq!(serving.clock_epoch, 9);
        assert_eq!(inspection.legacy_trust.unwrap().reason, "comparison failed");
        assert_eq!(
            inspection.action_quarantine.as_deref(),
            Some("canonical divergence")
        );
        assert_eq!(inspection.blocking_quarantines.items.len(), 2);
        assert_eq!(
            inspection.blocking_quarantines.items[0].reason.as_deref(),
            Some("canonical divergence")
        );
        assert!(inspection.blocking_quarantines.items[1].reason.is_none());
    }

    #[test]
    fn observable_only_incident_is_reported_despite_servable_record() {
        let (directory, connection) = database();
        connection
            .execute(
                "INSERT INTO action_serving_states (action_key, disposition, version) VALUES (?1, 'servable', 1)",
                [key()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO divergence_incidents VALUES \
                 (?1, 1, 'observable-only', 'committed', 'candidate', 'evidence', 'pin', 'generation', 'attempt', 'stdout mismatch')",
                [key()],
            )
            .unwrap();
        let inspection = inspect(&directory);
        assert!(inspection.observed);
        assert!(inspection.has_unresolved_divergence);
        assert!(inspection.action_quarantine.is_none());
        assert_eq!(inspection.serving.unwrap().disposition, "servable");
    }

    #[test]
    fn per_action_lists_are_ordered_and_have_explicit_truncation() {
        let (directory, connection) = database();
        for index in (0..=INSPECTION_ROW_LIMIT).rev() {
            connection
                .execute(
                    "INSERT INTO key_breakdowns VALUES (?1, ?2, 'sha256-v1', 'rabs.component.sha256.v1', ?3)",
                    params![key(), format!("component-{index:03}"), [index as u8; 32].as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO serving_blocking_quarantines VALUES (?1, 'object', ?2)",
                    params![key(), format!("object-{index:03}")],
                )
                .unwrap();
        }
        let inspection = inspect(&directory);
        assert!(inspection.observed);
        assert_eq!(inspection.breakdown.items.len(), INSPECTION_ROW_LIMIT);
        assert!(inspection.breakdown.truncated);
        assert_eq!(inspection.breakdown.items[0].component, "component-000");
        assert_eq!(inspection.breakdown.items[63].component, "component-063");
        assert_eq!(inspection.breakdown.items[0].digest_hex, "00".repeat(32));
        assert_eq!(
            inspection.blocking_quarantines.items.len(),
            INSPECTION_ROW_LIMIT
        );
        assert!(inspection.blocking_quarantines.truncated);
        connection
            .execute(
                "DELETE FROM key_breakdowns WHERE component = 'component-064'",
                [],
            )
            .unwrap();
        assert!(!inspect(&directory).breakdown.truncated);
    }

    #[test]
    fn malformed_digest_epoch_identifier_and_oversized_text_fail_explicitly() {
        let (directory, connection) = database();
        insert_entry(&connection);
        for mutation in [
            "UPDATE action_entries SET bytes = zeroblob(31)",
            "UPDATE action_entries SET bytes = zeroblob(32)",
            "UPDATE action_entries SET key_epoch = -1",
            "UPDATE action_entries SET key_epoch = 4294967296",
            "UPDATE action_entries SET projection_epoch = 'invalid'",
            "UPDATE action_entries SET algo = 'unknown'",
        ] {
            connection.execute_batch(mutation).unwrap();
            assert!(matches!(
                inspect_action(&directory.path().join("meta.sqlite"), &key()),
                Err(InspectionError::InvalidMetadata(_))
            ));
            connection
                .execute("DELETE FROM action_entries", [])
                .unwrap();
            insert_entry(&connection);
        }
        insert_publication(&connection);
        connection
            .execute(
                "UPDATE action_publications SET winner_attempt_hex = 'bad'",
                [],
            )
            .unwrap();
        assert!(matches!(
            inspect_action(&directory.path().join("meta.sqlite"), &key()),
            Err(InspectionError::InvalidMetadata(_))
        ));
        connection
            .execute("DELETE FROM action_publications", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO trust_states VALUES (?1, 'refused', ?2)",
                params![key(), "x".repeat(MAX_TEXT_BYTES + 1)],
            )
            .unwrap();
        assert!(matches!(
            inspect_action(&directory.path().join("meta.sqlite"), &key()),
            Err(InspectionError::InvalidMetadata(_))
        ));
    }

    #[test]
    fn winning_worker_is_not_attributed_across_generations() {
        let (directory, connection) = database();
        insert_publication(&connection);
        connection
            .execute(
                "UPDATE action_attempts SET generation_hex = ?1",
                [format!("{:032x}", 99)],
            )
            .unwrap();
        assert!(matches!(
            inspect_action(&directory.path().join("meta.sqlite"), &key()),
            Err(InspectionError::InvalidMetadata(_))
        ));
    }

    #[test]
    fn wal_writer_cannot_mix_sections_of_an_inspection_snapshot() {
        let (directory, writer) = database();
        writer.pragma_update(None, "journal_mode", "WAL").unwrap();
        insert_entry(&writer);
        writer
            .execute(
                "INSERT INTO action_trust_evaluations VALUES (?1, 1, 'pending', 'before write', 10)",
                [key()],
            )
            .unwrap();
        let path = directory.path().join("meta.sqlite");
        let mut reader =
            Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let transaction = reader
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .unwrap();
        // The real schema read pins the same snapshot as the public opener.
        let version = inspect_schema(&transaction).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        insert_publication(&writer);
        writer
            .execute(
                "INSERT INTO action_trust_evaluations VALUES (?1, 2, 'verified', 'after write', 20)",
                [key()],
            )
            .unwrap();
        writer.execute_batch("COMMIT").unwrap();
        let before = inspect_snapshot(&transaction, key(), version).unwrap();
        assert!(before.publication.is_none());
        assert_eq!(before.trust_evaluation.unwrap().reason, "before write");
        transaction.commit().unwrap();
        let after = inspect(&directory);
        assert!(after.publication.is_some());
        assert_eq!(after.trust_evaluation.unwrap().reason, "after write");
    }
}
