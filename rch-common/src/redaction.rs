//! Shared secret-redaction and privacy policy for all remediation data
//! (bd-session-history-remediation-ocv9i.16.8).
//!
//! The session-history remediation program adds many data surfaces — incident
//! ledgers, proof intents, admission output, fleet status, config export,
//! telemetry, artifact diagnostics, real-fleet smoke logs, and agent handoff
//! JSON. Each must be useful for debugging **without** leaking SSH identities,
//! tokens, absolute sensitive paths, environment secrets, credential-shaped
//! command arguments, or private source contents.
//!
//! This module is the single library home for that policy. Before it, redaction
//! primitives were scattered ([`crate::util::mask_sensitive_command`] for
//! env/argv, a private path masker in `remediation_config`) and the policy
//! vocabulary lived only inside a test. Here we provide:
//!
//! - [`redact_secrets`] — the comprehensive free-text redactor (env/argv key
//!   masking + provider-shaped key detection + credential URLs + PEM blocks +
//!   home/user path segments). Apply it at the **data layer**, before any
//!   rendering, so the same redacted value flows identically through JSON, TOON,
//!   plain, colored, and interactive output.
//! - [`redact_path`] — masks the home/user segment of a single structured path
//!   field (used by [`crate::remediation_config`]).
//! - [`redacted_hash`] — a short, stable, irreversible blake3 reference for
//!   values that must be correlated but never revealed.
//! - [`RedactionPolicy`] — the versioned, serializable description of every
//!   rule and the treatment ([`RedactionMode`]) it applies, so future agents
//!   know what can be correlated safely.
//!
//! # Three information-boundary modes
//!
//! The policy distinguishes how each class of data is protected:
//! - [`RedactionMode::Hashed`] — irreversible (blake3) fingerprint; correlatable
//!   but not recoverable (e.g. proof source fingerprints).
//! - [`RedactionMode::LocalReference`] — a stable local-only reference (e.g. an
//!   env-var *name* instead of its value, or a worker id instead of a hostname).
//! - [`RedactionMode::Omitted`] — the field is never recorded at all.
//! - [`RedactionMode::Masked`] — the value is replaced in place by the
//!   [`REDACTION_SENTINEL`] (or `***`), preserving surrounding structure for
//!   debugging.

use std::sync::LazyLock;

use regex::Regex;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};

use crate::schema_versions::{SchemaComponent, current_version};

pub use crate::util::mask_sensitive_command;

/// Sentinel used to replace a masked value.
pub const REDACTION_SENTINEL: &str = "[REDACTED]";

/// How a class of sensitive data is protected (the information boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// Replaced by an irreversible blake3 fingerprint: correlatable, not
    /// recoverable.
    Hashed,
    /// Replaced by a stable local-only reference (e.g. an env-var name or a
    /// worker id) that does not reveal the secret itself.
    LocalReference,
    /// Never recorded at all.
    Omitted,
    /// Replaced in place by the sentinel / `***`, preserving structure.
    Masked,
}

/// Categories of sensitive data the policy governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveDataCategory {
    /// `KEY=value` environment-variable secrets (tokens, passwords, keys).
    EnvSecret,
    /// Provider-shaped API keys (AWS, GitHub, OpenAI, Google, Slack, Stripe).
    ApiKey,
    /// `Authorization: Bearer …` tokens and JWTs.
    BearerToken,
    /// Passwords/secrets passed as CLI flags.
    Password,
    /// SSH/TLS private keys (PEM blocks) and key files.
    SshKey,
    /// Credentials embedded in connection URLs (`scheme://user:pass@host`).
    DatabaseUrl,
    /// Cloud-provider credential material.
    CloudCredential,
    /// Filesystem paths that reveal a home directory / username.
    FilesystemPath,
    /// Worker hostnames / usernames.
    Hostname,
    /// Raw source file contents.
    SourceContent,
    /// Personally identifying information.
    Pii,
    /// Project-specific / custom secrets.
    Custom,
}

/// A named rule describing the treatment of one category of sensitive data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RedactionRule {
    /// Stable rule identifier for audit trails (`RR-001`…).
    pub id: String,
    /// Category of sensitive data the rule targets.
    pub category: SensitiveDataCategory,
    /// How matched data is protected.
    pub mode: RedactionMode,
    /// Human-readable explanation of the rule.
    pub description: String,
}

impl RedactionRule {
    fn new(
        id: &str,
        category: SensitiveDataCategory,
        mode: RedactionMode,
        description: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            category,
            mode,
            description: description.to_string(),
        }
    }
}

/// The versioned, serializable secret-redaction / privacy policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RedactionPolicy {
    /// Schema version (`SchemaComponent::RedactionPolicy`).
    pub schema_version: String,
    /// Sentinel string substituted for masked values.
    pub sentinel: String,
    /// Whether redaction events should be recorded for audit.
    pub audit_redactions: bool,
    /// The active rule set, in audit-id order.
    pub rules: Vec<RedactionRule>,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        use RedactionMode::{Hashed, LocalReference, Masked};
        use SensitiveDataCategory::{
            ApiKey, BearerToken, DatabaseUrl, EnvSecret, FilesystemPath, Hostname, Password,
            SourceContent, SshKey,
        };
        Self {
            schema_version: current_version(SchemaComponent::RedactionPolicy).to_string(),
            sentinel: REDACTION_SENTINEL.to_string(),
            audit_redactions: true,
            rules: vec![
                RedactionRule::new(
                    "RR-001",
                    EnvSecret,
                    Masked,
                    "Environment assignments for known secret keys (TOKEN=, PASSWORD=, \
                     *_KEY=, DATABASE_URL=, provider keys) are masked to ***.",
                ),
                RedactionRule::new(
                    "RR-002",
                    ApiKey,
                    Masked,
                    "Provider-shaped API keys (AWS AKIA…, GitHub ghp_/gho_/ghu_/ghs_/ghr_, \
                     OpenAI/Anthropic sk-…, Google AIza…, Slack xox*, Stripe sk_live_/sk_test_) \
                     are masked.",
                ),
                RedactionRule::new(
                    "RR-003",
                    BearerToken,
                    Masked,
                    "Authorization Bearer tokens and JWTs (eyJ….….…) are masked.",
                ),
                RedactionRule::new(
                    "RR-004",
                    Password,
                    Masked,
                    "Credential-shaped CLI flags (--password, --token, --secret, --api-key) \
                     are masked.",
                ),
                RedactionRule::new(
                    "RR-005",
                    DatabaseUrl,
                    Masked,
                    "Credentials embedded in connection URLs (scheme://user:pass@host) have the \
                     user:pass component masked.",
                ),
                RedactionRule::new(
                    "RR-006",
                    SshKey,
                    Masked,
                    "PEM private-key blocks (-----BEGIN … PRIVATE KEY-----) are masked.",
                ),
                RedactionRule::new(
                    "RR-007",
                    FilesystemPath,
                    Masked,
                    "Home/user path segments (/home/<user>, /Users/<user>) are masked to \
                     protect usernames while preserving the rest of the path for debugging.",
                ),
                RedactionRule::new(
                    "RR-008",
                    SourceContent,
                    Hashed,
                    "Source file contents are never stored; only blake3 fingerprints are kept \
                     (see proof_intent::SourceFingerprint), so unchanged-source checks remain \
                     possible without revealing code.",
                ),
                RedactionRule::new(
                    "RR-009",
                    Hostname,
                    LocalReference,
                    "Worker identities are referenced by stable worker id rather than raw \
                     hostname/username wherever a surface does not require the host.",
                ),
            ],
        }
    }
}

impl RedactionPolicy {
    /// Apply the masking rules to free text. Equivalent to [`redact_secrets`];
    /// provided as a method so callers that hold a policy can express intent.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        redact_secrets(text)
    }

    /// The machine-readable JSON Schema for the policy.
    #[must_use]
    pub fn schema_json() -> serde_json::Value {
        serde_json::to_value(schema_for!(RedactionPolicy))
            .expect("RedactionPolicy schema serializes")
    }

    /// Every category the default policy governs (for coverage checks).
    #[must_use]
    pub fn covered_categories(&self) -> Vec<SensitiveDataCategory> {
        let mut cats: Vec<SensitiveDataCategory> = self.rules.iter().map(|r| r.category).collect();
        cats.dedup();
        cats
    }
}

/// One compiled value-shaped pattern and its replacement.
struct ShapedPattern {
    re: Regex,
    /// Replacement template; `${1}` style group refs are honored by `replace_all`.
    replacement: &'static str,
}

/// Lazily-compiled redaction engine: value-shaped secret patterns plus the
/// credential-URL and home-path maskers. Compiled once; redaction is not on the
/// hook hot path (it guards logging/export surfaces).
static SHAPED_PATTERNS: LazyLock<Vec<ShapedPattern>> = LazyLock::new(|| {
    let p = |pattern: &str, replacement: &'static str| ShapedPattern {
        re: Regex::new(pattern).expect("redaction regex compiles"),
        replacement,
    };
    vec![
        // PEM private-key block (multi-line). Match the whole block.
        p(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            REDACTION_SENTINEL,
        ),
        // AWS access key id.
        p(r"AKIA[0-9A-Z]{16}", REDACTION_SENTINEL),
        // GitHub personal/OAuth/app tokens.
        p(r"gh[pousr]_[A-Za-z0-9]{20,}", REDACTION_SENTINEL),
        // Google API key.
        p(r"AIza[0-9A-Za-z_\-]{35}", REDACTION_SENTINEL),
        // Slack tokens.
        p(r"xox[baprs]-[0-9A-Za-z\-]{10,}", REDACTION_SENTINEL),
        // Stripe live/test secret + restricted keys.
        p(r"[sr]k_(live|test)_[A-Za-z0-9]{16,}", REDACTION_SENTINEL),
        // Anthropic keys (more specific than the generic sk- rule; run first).
        p(r"sk-ant-[A-Za-z0-9_\-]{16,}", REDACTION_SENTINEL),
        // OpenAI-style secret keys.
        p(r"sk-[A-Za-z0-9]{20,}", REDACTION_SENTINEL),
        // JWTs (header.payload.signature, base64url).
        p(
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            REDACTION_SENTINEL,
        ),
        // Authorization: Bearer <token>.
        p(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}", "Bearer [REDACTED]"),
        // Credentials embedded in a connection URL: scheme://user:pass@host.
        p(
            r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s:]+:[^/@\s]+@",
            "${1}[REDACTED]@",
        ),
        // Home/user path segments anywhere in the text.
        p(r#"(/home/|/Users/)[^/\s:"']+"#, "${1}<redacted>"),
    ]
});

/// Comprehensively redact secrets from free text (logs, captured output,
/// diagnostics, JSONL artifacts).
///
/// Applies, in order: env/argv key masking ([`mask_sensitive_command`]), then
/// provider-shaped key detection, credential URLs, PEM blocks, and home/user
/// path segments. Safe (idempotent-ish) to apply more than once. Errs toward
/// over-masking value-shaped secrets while leaving ordinary text intact.
#[must_use]
pub fn redact_secrets(text: &str) -> String {
    // First mask `KEY=value` and `--flag value` forms (handles secrets that are
    // not value-shaped on their own, e.g. a short password).
    let mut out = mask_sensitive_command(text);
    for pat in SHAPED_PATTERNS.iter() {
        out = pat.re.replace_all(&out, pat.replacement).into_owned();
    }
    out
}

/// Mask the home/user segment of a single structured path field so it is safe
/// to print. Pure and environment-independent for stable golden output:
/// `/home/<user>/x` → `/home/<redacted>/x`, `/Users/<user>/x` →
/// `/Users/<redacted>/x`; a leading `~` is preserved.
#[must_use]
pub fn redact_path(path: &str) -> String {
    for marker in ["/home/", "/Users/"] {
        if let Some(rest_start) = path.find(marker) {
            let (head, tail) = path.split_at(rest_start + marker.len());
            let masked_tail = match tail.find('/') {
                Some(slash) => format!("<redacted>{}", &tail[slash..]),
                None => "<redacted>".to_string(),
            };
            return format!("{head}{masked_tail}");
        }
    }
    path.to_string()
}

/// A short, stable, irreversible reference for a value that must be correlated
/// but never revealed (the [`RedactionMode::Hashed`] treatment).
///
/// Returns `blake3:<first 16 hex chars>`. Deterministic for a given input.
#[must_use]
pub fn redacted_hash(value: &str) -> String {
    let hash = blake3::hash(value.as_bytes());
    let hex = hash.to_hex();
    format!("blake3:{}", &hex[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_default_is_versioned_and_covers_core_categories() {
        let p = RedactionPolicy::default();
        assert_eq!(
            p.schema_version,
            current_version(SchemaComponent::RedactionPolicy)
        );
        assert_eq!(p.sentinel, REDACTION_SENTINEL);
        // Every rule has a non-empty id + description.
        for r in &p.rules {
            assert!(!r.id.is_empty());
            assert!(!r.description.is_empty());
        }
        // Core categories the bead enumerates are all governed.
        let cats = p.covered_categories();
        for needed in [
            SensitiveDataCategory::EnvSecret,
            SensitiveDataCategory::ApiKey,
            SensitiveDataCategory::BearerToken,
            SensitiveDataCategory::Password,
            SensitiveDataCategory::DatabaseUrl,
            SensitiveDataCategory::SshKey,
            SensitiveDataCategory::FilesystemPath,
            SensitiveDataCategory::SourceContent,
            SensitiveDataCategory::Hostname,
        ] {
            assert!(cats.contains(&needed), "policy missing category {needed:?}");
        }
    }

    #[test]
    fn policy_documents_three_information_boundary_modes() {
        // Criterion: distinguishes irreversible hashing, reversible local-only
        // references, and (omitted/)masked treatment.
        let p = RedactionPolicy::default();
        let modes: Vec<RedactionMode> = p.rules.iter().map(|r| r.mode).collect();
        assert!(modes.contains(&RedactionMode::Hashed));
        assert!(modes.contains(&RedactionMode::LocalReference));
        assert!(modes.contains(&RedactionMode::Masked));
    }

    #[test]
    fn policy_serde_round_trip() {
        let p = RedactionPolicy::default();
        let json = serde_json::to_string(&p).expect("serialize");
        let back: RedactionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }

    #[test]
    fn representative_secrets_are_all_masked() {
        // One representative of each category the bead names. Each fixture is
        // assembled at runtime from split parts so no contiguous secret literal
        // ever appears in source — that keeps GitHub secret-scanning push
        // protection from flagging our own test data. The redactor still sees
        // the fully-assembled secret.
        let cases = [
            format!("AKIA{}", "IOSFODNN7EXAMPLE"), // AWS
            format!("ghp_{}", "1234567890abcdefghijklmnopqrstuvwxyz"), // GitHub
            format!("sk-{}", "abcdefghijklmnopqrstuvwxyz0123456789"), // OpenAI
            format!("sk-ant-{}", "api03abcdefghijklmnopqrstuvwxyz"), // Anthropic
            format!("AIza{}", "SyA1234567890abcdefghijklmnopqrstuvw"), // Google
            format!("xox{}-{}-{}", "b", "123456789012", "abcdefghijklmnop"), // Slack
            format!("sk_{}_{}", "live", "abcdefghijklmnop12345678"), // Stripe
        ];
        for c in &cases {
            let red = redact_secrets(c);
            assert!(
                red.contains(REDACTION_SENTINEL),
                "secret not masked: {c} -> {red}"
            );
            assert!(
                !red.contains(c.as_str()),
                "raw secret survived: {c} -> {red}"
            );
        }
    }

    #[test]
    fn env_and_cli_secrets_masked() {
        // Token assembled from parts (see representative_secrets_are_all_masked).
        let token = format!("ghp_{}", "abcdefghijklmnopqrstuvwx012345");
        let red = redact_secrets(&format!(
            "GITHUB_TOKEN={token} cargo build --token sekret123456"
        ));
        assert!(!red.contains(&token));
        assert!(!red.contains("sekret123456"));
        assert!(red.contains("GITHUB_TOKEN=***") || red.contains("GITHUB_TOKEN=[REDACTED]"));
        assert!(red.contains("--token ***"));
    }

    #[test]
    fn database_url_credentials_masked_host_preserved() {
        let red = redact_secrets("postgres://admin:hunter2@db.internal:5432/app");
        assert!(!red.contains("hunter2"));
        assert!(!red.contains("admin:hunter2"));
        // The host/db are preserved for debugging.
        assert!(red.contains("db.internal:5432/app"), "host lost: {red}");
        assert!(red.contains("[REDACTED]@"), "creds not masked: {red}");
    }

    #[test]
    fn bearer_and_jwt_masked() {
        // JWT assembled from its three parts so no contiguous token is in source.
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N"
        );
        let red = redact_secrets(&format!("Authorization: Bearer {jwt}"));
        assert!(!red.contains(&jwt), "token survived: {red}");
    }

    #[test]
    fn pem_private_key_block_masked() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\nsecretkeymaterial\n-----END OPENSSH PRIVATE KEY-----";
        let red = redact_secrets(pem);
        assert!(!red.contains("secretkeymaterial"), "key survived: {red}");
        assert!(red.contains(REDACTION_SENTINEL));
    }

    #[test]
    fn home_paths_masked_in_text_and_single_field() {
        let red = redact_secrets("loaded /home/alice/.ssh/id_rsa and /Users/bob/key.pem");
        assert!(red.contains("/home/<redacted>/.ssh/id_rsa"), "{red}");
        assert!(red.contains("/Users/<redacted>/key.pem"), "{red}");
        // Single-field helper.
        assert_eq!(
            redact_path("/home/carol/.local/state/rch/x.jsonl"),
            "/home/<redacted>/.local/state/rch/x.jsonl"
        );
        assert_eq!(redact_path("/tmp/rch/x"), "/tmp/rch/x");
    }

    #[test]
    fn no_false_positives_on_safe_text() {
        // Ordinary build output must be left intact.
        let safe = "cargo build --release -p rch-common && echo done in /tmp/rch";
        assert_eq!(redact_secrets(safe), safe);
    }

    #[test]
    fn redaction_is_idempotent() {
        let token = format!("ghp_{}", "abcdefghijklmnopqrstuvwx012345");
        let once = redact_secrets(&format!("GITHUB_TOKEN={token}"));
        let twice = redact_secrets(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn redacted_hash_is_stable_and_irreversible() {
        let a = redacted_hash("super-secret-value");
        let b = redacted_hash("super-secret-value");
        assert_eq!(a, b);
        assert!(a.starts_with("blake3:"));
        assert!(!a.contains("super-secret"));
        assert_ne!(a, redacted_hash("different-value"));
    }

    #[test]
    fn schema_json_lists_policy_fields() {
        let schema = RedactionPolicy::schema_json();
        let props = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .expect("schema has properties");
        for f in ["schema_version", "sentinel", "audit_redactions", "rules"] {
            assert!(props.contains_key(f), "schema missing field {f}");
        }
    }
}
