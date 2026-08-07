//! Secret redaction + nonshareable classification (bead S007; plan
//! §106).
//!
//! Secrets reach actions ONLY through stable logical capability
//! slots, and the plaintext never escapes:
//!
//! - [`SecretValue`] prints as `[REDACTED:slot]` from both `Debug`
//!   and `Display`, derives neither `Clone` nor any serializer, and
//!   exposes its bytes only through the explicit, audited
//!   [`SecretValue::expose`];
//! - breakdowns/logs/events/bundles carry the SLOT NAME, never the
//!   value (there is no API that returns the plaintext for them);
//! - child diagnostics are scrubbed where reliably detectable:
//!   occurrences of the plaintext are replaced by the slot marker;
//!   secrets too short or non-textual to detect reliably are FLAGGED
//!   so the whole artifact classifies nonshareable — a silent
//!   best-effort scrub is not an answer;
//! - finalization WIPES the value (zeroed in place); exposure after
//!   the wipe is a typed refusal;
//! - an output-affecting secret follows the opaque-digest-or-
//!   noncacheable rule: it enters the key as an opaque digest or the
//!   action does not cache. The enum has NO plaintext arm.

use crate::result_identity::TypedDigest;

/// Minimum plaintext length (bytes) for reliable detection in child
/// diagnostics. Shorter secrets false-positive too easily to scrub
/// silently — they escalate to nonshareable instead.
pub const MIN_DETECTABLE_SECRET_LEN: usize = 8;

/// A secret bound to its stable logical capability slot.
///
/// No `Clone`, no serializer: copies of the plaintext do not
/// multiply, and nothing serializes it by accident.
pub struct SecretValue {
    slot: String,
    bytes: Vec<u8>,
    wiped: bool,
}

/// Typed refusal for post-wipe access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretWiped {
    /// The slot whose value was already finalized.
    pub slot: String,
}

impl SecretValue {
    /// Bind a secret to its logical slot.
    #[must_use]
    pub fn new(slot: &str, bytes: Vec<u8>) -> Self {
        Self {
            slot: slot.to_owned(),
            bytes,
            wiped: false,
        }
    }

    /// The stable logical slot name (the ONLY identity that appears
    /// in breakdowns, logs, events, and bundles).
    #[must_use]
    pub fn slot(&self) -> &str {
        &self.slot
    }

    /// The redaction marker this secret prints as.
    #[must_use]
    pub fn marker(&self) -> String {
        format!("[REDACTED:{}]", self.slot)
    }

    /// Explicit, audited access to the plaintext (exec-time only).
    ///
    /// # Errors
    /// [`SecretWiped`] after finalization.
    pub fn expose(&self) -> Result<&[u8], SecretWiped> {
        if self.wiped {
            return Err(SecretWiped {
                slot: self.slot.clone(),
            });
        }
        Ok(&self.bytes)
    }

    /// Finalization wipe: zero the plaintext in place. Idempotent.
    pub fn wipe(&mut self) {
        self.bytes.fill(0);
        self.wiped = true;
    }

    /// Whether finalization has wiped the value.
    #[must_use]
    pub const fn is_wiped(&self) -> bool {
        self.wiped
    }

    #[cfg(test)]
    fn raw_for_test(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl core::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[REDACTED:{}]", self.slot)
    }
}

impl core::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[REDACTED:{}]", self.slot)
    }
}

/// How an output-affecting secret participates in the action key.
/// There is NO arm carrying plaintext — the rule is structural.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKeying {
    /// The secret keys as an opaque domain-separated digest.
    OpaqueDigest(TypedDigest),
    /// No opaque digest available: the action does not cache.
    NonCacheable,
}

/// Decide the keying for an output-affecting secret.
#[must_use]
pub fn output_affecting_keying(opaque_digest: Option<TypedDigest>) -> SecretKeying {
    opaque_digest.map_or(SecretKeying::NonCacheable, SecretKeying::OpaqueDigest)
}

/// Shareability classification for an artifact/log after redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shareability {
    /// Every involved secret was reliably scrubbed: shareable.
    Shareable,
    /// Some secret was NOT reliably detectable: the artifact never
    /// leaves the box (offending slots named).
    Nonshareable {
        /// Slots whose secrets could not be reliably scrubbed.
        undetectable_slots: Vec<String>,
    },
}

/// A scrubbed diagnostic stream plus its classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutcome {
    /// The scrubbed text.
    pub text: String,
    /// Occurrences replaced.
    pub replaced: u32,
    /// The shareability verdict.
    pub shareability: Shareability,
}

/// Scrub child diagnostics: replace reliably-detectable plaintext
/// with slot markers; flag what cannot be scrubbed reliably.
#[must_use]
pub fn redact_diagnostics(text: &str, secrets: &[&SecretValue]) -> RedactionOutcome {
    let mut scrubbed = text.to_owned();
    let mut replaced = 0_u32;
    let mut undetectable: Vec<String> = Vec::new();
    for secret in secrets {
        let detectable = secret
            .expose()
            .ok()
            .filter(|bytes| bytes.len() >= MIN_DETECTABLE_SECRET_LEN)
            .and_then(|bytes| core::str::from_utf8(bytes).ok());
        match detectable {
            Some(plaintext) => {
                let count = scrubbed.matches(plaintext).count();
                if count > 0 {
                    scrubbed = scrubbed.replace(plaintext, &secret.marker());
                    replaced += u32::try_from(count).unwrap_or(u32::MAX);
                }
            }
            None => undetectable.push(secret.slot().to_owned()),
        }
    }
    let shareability = if undetectable.is_empty() {
        Shareability::Shareable
    } else {
        Shareability::Nonshareable {
            undetectable_slots: undetectable,
        }
    };
    RedactionOutcome {
        text: scrubbed,
        replaced,
        shareability,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    const PLAINTEXT: &str = "ghp_supersecrettoken12345";

    fn secret() -> SecretValue {
        SecretValue::new("cargo-registry-token", PLAINTEXT.as_bytes().to_vec())
    }

    #[test]
    fn secret_bearing_fixtures_leave_zero_plaintext_traces() {
        // THE acceptance: every surface a secret could reach — Debug,
        // Display, keying, scrubbed diagnostics — carries no
        // plaintext.
        let s = secret();
        let surfaces = [
            format!("{s:?}"),
            format!("{s}"),
            format!(
                "{:?}",
                output_affecting_keying(Some(TypedDigest {
                    algorithm: DigestAlgorithm::Sha256V1,
                    domain: "rabs.secret-opaque.v1",
                    bytes: [7; 32],
                }))
            ),
            redact_diagnostics(
                &format!("error: auth failed for token {PLAINTEXT} (retried)"),
                &[&s],
            )
            .text,
        ];
        for surface in &surfaces {
            assert!(
                !surface.contains(PLAINTEXT),
                "plaintext leaked into: {surface}"
            );
        }
        assert!(surfaces[0].contains("[REDACTED:cargo-registry-token]"));
    }

    #[test]
    fn diagnostics_scrubbing_replaces_every_occurrence() {
        let s = secret();
        let noisy = format!("token={PLAINTEXT}; retry with {PLAINTEXT} failed");
        let outcome = redact_diagnostics(&noisy, &[&s]);
        assert_eq!(outcome.replaced, 2);
        assert_eq!(
            outcome.text,
            "token=[REDACTED:cargo-registry-token]; retry with [REDACTED:cargo-registry-token] failed"
        );
        assert_eq!(outcome.shareability, Shareability::Shareable);
    }

    #[test]
    fn undetectable_secrets_classify_nonshareable_not_silently_scrubbed() {
        // A short secret would false-positive as a substring; a
        // binary secret has no textual form. Neither scrubs silently:
        // the artifact classifies NONSHAREABLE with the slots named.
        let short = SecretValue::new("pin", b"1234".to_vec());
        let binary = SecretValue::new(
            "hmac-key",
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04],
        );
        let outcome = redact_diagnostics("harmless text", &[&short, &binary]);
        assert_eq!(
            outcome.shareability,
            Shareability::Nonshareable {
                undetectable_slots: vec!["pin".into(), "hmac-key".into()],
            }
        );
        assert_eq!(outcome.replaced, 0);
    }

    #[test]
    fn output_affecting_secrets_key_opaquely_or_not_at_all() {
        // THE rule: opaque digest when available, noncacheable when
        // not — and the enum has no arm that could carry plaintext
        // (exhaustive match proves it).
        let digest = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.secret-opaque.v1",
            bytes: [7; 32],
        };
        match output_affecting_keying(Some(digest.clone())) {
            SecretKeying::OpaqueDigest(d) => assert_eq!(d, digest),
            SecretKeying::NonCacheable => panic!("digest available: keys opaquely"),
        }
        assert_eq!(output_affecting_keying(None), SecretKeying::NonCacheable);
    }

    #[test]
    fn finalization_wipes_and_later_exposure_refuses() {
        let mut s = secret();
        assert_eq!(s.expose().expect("live"), PLAINTEXT.as_bytes());
        s.wipe();
        // The buffer really is zeroed, not just flagged.
        assert!(s.raw_for_test().iter().all(|&b| b == 0));
        assert!(s.is_wiped());
        assert_eq!(
            s.expose(),
            Err(SecretWiped {
                slot: "cargo-registry-token".into(),
            })
        );
        // Idempotent.
        s.wipe();
        assert!(s.is_wiped());
    }
}
