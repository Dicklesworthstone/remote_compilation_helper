//! Durable proof-intent schema and store (bd-session-history-remediation-ocv9i.5.2).
//!
//! When a proof-mode attempt is *denied*, RCH records a [`ProofIntent`]: enough
//! to replay (or refuse to replay) the attempt later, and safe to reference in
//! a Beads handoff. The record is **redaction-safe by construction** — it stores
//! a `command_digest` (a hash, never the raw command line), an `env_allowlist`
//! of variable *names* (never their values), and source *fingerprints* (hashes,
//! never content). There is deliberately no field that could carry a secret;
//! `test_no_raw_or_secret_fields` enforces that.
//!
//! The [`ProofIntentStore`] is an append-only JSONL log, deduplicated by
//! `intent_id` (latest write wins) and corruption-tolerant on read, mirroring
//! [`crate::incident_ledger`]. [`validate_replay`] decides whether a stored
//! intent may be replayed given the current revision / source fingerprints /
//! age, honoring the intent's [`StaleSourcePolicy`] and [`ReplayConstraints`].

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use schemars::schema::RootSchema;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};

use crate::incident::IncidentReasonCode;
use crate::schema_versions::{SchemaComponent, current_version};

/// A source file's identity by hash (never its contents).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceFingerprint {
    /// Path relative to the project root.
    pub path: String,
    /// blake3 hex digest of the file.
    pub blake3: String,
}

/// How to treat source that changed since the intent was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaleSourcePolicy {
    /// Replay only if the source is byte-identical (fingerprints match).
    RejectIfChanged,
    /// Replay even if source changed (the proof was source-independent).
    AllowIfChanged,
    /// Never replay — the intent is informational only.
    AlwaysReject,
}

/// Constraints that must hold for a stored intent to be replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ReplayConstraints {
    /// Replay only at the same repo revision.
    #[serde(default)]
    pub require_same_revision: bool,
    /// Replay only if every recorded source fingerprint still matches.
    #[serde(default)]
    pub require_unchanged_sources: bool,
    /// Maximum age (seconds) before the intent is too old to replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
}

/// A durable record of a denied proof attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProofIntent {
    /// Schema version (`SchemaComponent::ProofIntent`).
    pub schema_version: String,
    /// Stable id (see [`derive_intent_id`]).
    pub intent_id: String,
    /// Hash of the classified command — NOT the raw command line.
    pub command_digest: String,
    /// Working directory the command ran in.
    pub cwd: String,
    /// Repo revision (e.g. git rev), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_revision: Option<String>,
    /// Source fingerprints (hashes) captured at denial time.
    #[serde(default)]
    pub source_fingerprints: Vec<SourceFingerprint>,
    /// Names of env vars that were allowlisted (never their values).
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    /// Effective target-dir policy.
    pub target_dir_policy: String,
    /// Cargo package scope (`-p` selection).
    #[serde(default)]
    pub package_scope: Vec<String>,
    /// Test scope (test filters), if any.
    #[serde(default)]
    pub test_scope: Vec<String>,
    /// Explicitly requested worker, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_worker: Option<String>,
    /// Explicitly requested profile, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_profile: Option<String>,
    /// Why the proof was denied (stable incident reason vocabulary).
    /// Serializes as its `RCH-Innn` string; described to schemars as a string.
    #[schemars(with = "String")]
    pub denial_reason: IncidentReasonCode,
    /// Constraints for a future replay.
    pub replay_constraints: ReplayConstraints,
    /// Stale-source policy.
    pub stale_source_policy: StaleSourcePolicy,
    /// Denial time as Unix epoch milliseconds (caller-supplied → deterministic).
    pub recorded_at_unix_ms: u64,
    /// Free-form, redaction-safe details.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl ProofIntent {
    /// Construct an intent, stamping the schema version and deriving the
    /// `intent_id` from (command_digest, cwd, repo_revision).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_digest: impl Into<String>,
        cwd: impl Into<String>,
        repo_revision: Option<String>,
        target_dir_policy: impl Into<String>,
        denial_reason: IncidentReasonCode,
        stale_source_policy: StaleSourcePolicy,
        replay_constraints: ReplayConstraints,
        recorded_at_unix_ms: u64,
    ) -> Self {
        let command_digest = command_digest.into();
        let cwd = cwd.into();
        let intent_id = derive_intent_id(&command_digest, &cwd, repo_revision.as_deref());
        Self {
            schema_version: proof_intent_schema_version().to_string(),
            intent_id,
            command_digest,
            cwd,
            repo_revision,
            source_fingerprints: Vec::new(),
            env_allowlist: Vec::new(),
            target_dir_policy: target_dir_policy.into(),
            package_scope: Vec::new(),
            test_scope: Vec::new(),
            requested_worker: None,
            requested_profile: None,
            denial_reason,
            replay_constraints,
            stale_source_policy,
            recorded_at_unix_ms,
            details: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_source_fingerprints(mut self, fps: Vec<SourceFingerprint>) -> Self {
        self.source_fingerprints = fps;
        self
    }

    #[must_use]
    pub fn with_env_allowlist(mut self, names: Vec<String>) -> Self {
        self.env_allowlist = names;
        self
    }
}

/// Stable intent id: `pi-<blake3(command_digest|cwd|revision)[..16]>`.
#[must_use]
pub fn derive_intent_id(command_digest: &str, cwd: &str, repo_revision: Option<&str>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(command_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(cwd.as_bytes());
    hasher.update(b"\0");
    hasher.update(repo_revision.unwrap_or("").as_bytes());
    let hex = hasher.finalize().to_hex();
    format!("pi-{}", &hex[..16])
}

/// The current proof-intent schema version.
#[must_use]
pub fn proof_intent_schema_version() -> &'static str {
    current_version(SchemaComponent::ProofIntent)
}

/// Export the JSON Schema for [`ProofIntent`].
#[must_use]
pub fn proof_intent_schema() -> RootSchema {
    schema_for!(ProofIntent)
}

/// Current state used to decide whether a stored intent may be replayed.
#[derive(Debug, Clone, Default)]
pub struct ReplayContext {
    pub current_revision: Option<String>,
    pub current_fingerprints: Vec<SourceFingerprint>,
    pub age_secs: u64,
}

/// The replay decision for a stored intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    Replayable,
    Rejected {
        reason: IncidentReasonCode,
        detail: String,
    },
}

/// Decide whether `intent` may be replayed in `ctx`, honoring its stale-source
/// policy and replay constraints.
#[must_use]
pub fn validate_replay(intent: &ProofIntent, ctx: &ReplayContext) -> ReplayDecision {
    if intent.stale_source_policy == StaleSourcePolicy::AlwaysReject {
        return ReplayDecision::Rejected {
            reason: IncidentReasonCode::ProofRefusal,
            detail: "intent is informational only (always_reject)".to_string(),
        };
    }
    if let Some(max) = intent.replay_constraints.max_age_secs
        && ctx.age_secs > max
    {
        return ReplayDecision::Rejected {
            reason: IncidentReasonCode::ProofRefusal,
            detail: format!("intent age {}s exceeds max {}s", ctx.age_secs, max),
        };
    }
    if intent.replay_constraints.require_same_revision
        && intent.repo_revision != ctx.current_revision
    {
        return ReplayDecision::Rejected {
            reason: IncidentReasonCode::ProofRefusal,
            detail: "repo revision changed since intent was recorded".to_string(),
        };
    }
    let must_match = intent.replay_constraints.require_unchanged_sources
        || intent.stale_source_policy == StaleSourcePolicy::RejectIfChanged;
    if must_match && !fingerprints_match(&intent.source_fingerprints, &ctx.current_fingerprints) {
        return ReplayDecision::Rejected {
            reason: IncidentReasonCode::ProofRefusal,
            detail: "source fingerprint mismatch (source changed)".to_string(),
        };
    }
    ReplayDecision::Replayable
}

/// Exact-set fingerprint equality (path → blake3), order-independent.
fn fingerprints_match(recorded: &[SourceFingerprint], current: &[SourceFingerprint]) -> bool {
    if recorded.len() != current.len() {
        return false;
    }
    let map: BTreeMap<&str, &str> = current
        .iter()
        .map(|f| (f.path.as_str(), f.blake3.as_str()))
        .collect();
    recorded
        .iter()
        .all(|f| map.get(f.path.as_str()) == Some(&f.blake3.as_str()))
}

/// Append-only, dedup-by-`intent_id`, corruption-tolerant proof-intent store.
#[derive(Debug, Clone)]
pub struct ProofIntentStore {
    path: PathBuf,
}

impl ProofIntentStore {
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append an intent. Duplicate `intent_id`s are tolerated on write
    /// (latest-wins is resolved on read), so `put` stays O(1) on the hot path.
    pub fn put(&self, intent: &ProofIntent) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(intent)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()
    }

    /// All current intents, deduplicated by `intent_id` (latest write wins),
    /// in first-seen order. Corrupt lines are skipped.
    #[must_use]
    pub fn all(&self) -> Vec<ProofIntent> {
        let file = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        // Preserve first-seen order, but let a later record replace an earlier
        // one with the same id.
        let mut order: Vec<String> = Vec::new();
        let mut latest: BTreeMap<String, ProofIntent> = BTreeMap::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { break };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(intent) = serde_json::from_str::<ProofIntent>(trimmed) {
                if !latest.contains_key(&intent.intent_id) {
                    order.push(intent.intent_id.clone());
                }
                latest.insert(intent.intent_id.clone(), intent);
            }
        }
        order
            .into_iter()
            .filter_map(|id| latest.remove(&id))
            .collect()
    }

    /// Fetch a single intent by id (latest wins).
    #[must_use]
    pub fn get(&self, intent_id: &str) -> Option<ProofIntent> {
        self.all().into_iter().find(|i| i.intent_id == intent_id)
    }

    /// Intents matching a denial reason.
    #[must_use]
    pub fn by_reason(&self, reason: IncidentReasonCode) -> Vec<ProofIntent> {
        self.all()
            .into_iter()
            .filter(|i| i.denial_reason == reason)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> ProofIntent {
        ProofIntent::new(
            "blake3:abc123",
            "/data/projects/foo",
            Some("rev-1".to_string()),
            "pooled",
            IncidentReasonCode::ProofRefusal,
            StaleSourcePolicy::RejectIfChanged,
            ReplayConstraints {
                require_same_revision: true,
                require_unchanged_sources: true,
                max_age_secs: Some(3600),
            },
            1_700_000_000_000,
        )
        .with_source_fingerprints(vec![SourceFingerprint {
            path: "src/lib.rs".to_string(),
            blake3: "deadbeef".to_string(),
        }])
        .with_env_allowlist(vec![
            "CARGO_TARGET_DIR".to_string(),
            "RUSTFLAGS".to_string(),
        ])
    }

    #[test]
    fn test_no_raw_or_secret_fields() {
        // The record must never carry a raw command or any secret value.
        let v = serde_json::to_value(intent()).unwrap();
        let obj = v.as_object().unwrap();
        for forbidden in [
            "command",
            "raw_command",
            "env",
            "env_values",
            "secret",
            "password",
            "token",
        ] {
            assert!(
                !obj.contains_key(forbidden),
                "must not expose `{forbidden}`"
            );
        }
        // Only the digest + allowlisted NAMES survive.
        assert!(obj.contains_key("command_digest"));
        assert_eq!(v["env_allowlist"][0], "CARGO_TARGET_DIR");
    }

    #[test]
    fn intent_id_is_stable_and_derived() {
        let a = derive_intent_id("d", "/cwd", Some("r"));
        let b = derive_intent_id("d", "/cwd", Some("r"));
        assert_eq!(a, b);
        assert!(a.starts_with("pi-"));
        assert_ne!(a, derive_intent_id("d", "/cwd", Some("r2")));
        assert_eq!(
            intent().intent_id,
            derive_intent_id("blake3:abc123", "/data/projects/foo", Some("rev-1"))
        );
    }

    #[test]
    fn schema_version_stamped_and_versioned() {
        assert_eq!(intent().schema_version, "1.0.0");
        assert_eq!(proof_intent_schema_version(), "1.0.0");
        let text = serde_json::to_string(&proof_intent_schema()).unwrap();
        assert!(text.contains("ProofIntent"));
        for f in [
            "command_digest",
            "intent_id",
            "denial_reason",
            "replay_constraints",
            "stale_source_policy",
        ] {
            assert!(text.contains(f), "schema omits {f}");
        }
    }

    #[test]
    fn serde_roundtrips() {
        let i = intent();
        let back: ProofIntent = serde_json::from_str(&serde_json::to_string(&i).unwrap()).unwrap();
        assert_eq!(i, back);
    }

    #[test]
    fn replay_rejected_on_fingerprint_mismatch() {
        let i = intent();
        // Same revision, but the source hash changed.
        let ctx = ReplayContext {
            current_revision: Some("rev-1".to_string()),
            current_fingerprints: vec![SourceFingerprint {
                path: "src/lib.rs".to_string(),
                blake3: "CHANGED".to_string(),
            }],
            age_secs: 10,
        };
        match validate_replay(&i, &ctx) {
            ReplayDecision::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::ProofRefusal);
                assert!(detail.contains("fingerprint"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn replay_ok_when_unchanged() {
        let i = intent();
        let ctx = ReplayContext {
            current_revision: Some("rev-1".to_string()),
            current_fingerprints: vec![SourceFingerprint {
                path: "src/lib.rs".to_string(),
                blake3: "deadbeef".to_string(),
            }],
            age_secs: 10,
        };
        assert_eq!(validate_replay(&i, &ctx), ReplayDecision::Replayable);
    }

    #[test]
    fn replay_rejected_on_revision_change_and_age() {
        let i = intent();
        let rev = ReplayContext {
            current_revision: Some("rev-2".to_string()),
            current_fingerprints: i.source_fingerprints.clone(),
            age_secs: 10,
        };
        assert!(matches!(
            validate_replay(&i, &rev),
            ReplayDecision::Rejected { .. }
        ));

        let old = ReplayContext {
            current_revision: Some("rev-1".to_string()),
            current_fingerprints: i.source_fingerprints.clone(),
            age_secs: 7200, // > max_age 3600
        };
        match validate_replay(&i, &old) {
            ReplayDecision::Rejected { detail, .. } => assert!(detail.contains("age")),
            other => panic!("expected age rejection, got {other:?}"),
        }
    }

    #[test]
    fn always_reject_policy_never_replays() {
        let mut i = intent();
        i.stale_source_policy = StaleSourcePolicy::AlwaysReject;
        let ctx = ReplayContext {
            current_revision: i.repo_revision.clone(),
            current_fingerprints: i.source_fingerprints.clone(),
            age_secs: 0,
        };
        assert!(matches!(
            validate_replay(&i, &ctx),
            ReplayDecision::Rejected { .. }
        ));
    }

    #[test]
    fn store_dedups_duplicate_intents() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofIntentStore::with_path(dir.path().join("proofs.jsonl"));
        let i = intent();
        store.put(&i).unwrap();
        store.put(&i).unwrap(); // duplicate intent_id
        // A later write with the same id replaces (latest wins, one record).
        let mut updated = i.clone();
        updated.target_dir_policy = "isolated".to_string();
        store.put(&updated).unwrap();

        let all = store.all();
        assert_eq!(all.len(), 1, "duplicates dedup by intent_id");
        assert_eq!(all[0].target_dir_policy, "isolated", "latest write wins");
    }

    #[test]
    fn store_query_and_corruption_tolerance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proofs.jsonl");
        let store = ProofIntentStore::with_path(&path);
        store.put(&intent()).unwrap();
        // Inject a corrupt line; it must be skipped, not crash the read.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{{ not json").unwrap();
        }
        let mut other = ProofIntent::new(
            "blake3:zzz",
            "/data/projects/bar",
            None,
            "pooled",
            IncidentReasonCode::ProofRefusal,
            StaleSourcePolicy::AllowIfChanged,
            ReplayConstraints::default(),
            1_700_000_000_001,
        );
        other.requested_worker = Some("css".to_string());
        store.put(&other).unwrap();

        assert_eq!(store.all().len(), 2);
        assert_eq!(store.by_reason(IncidentReasonCode::ProofRefusal).len(), 2);
        assert!(store.get(&other.intent_id).is_some());
        assert!(store.get("pi-nonexistent").is_none());
    }

    #[test]
    fn missing_store_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofIntentStore::with_path(dir.path().join("nope.jsonl"));
        assert!(store.all().is_empty());
    }
}
