//! T027, the secret-policy family: paths that LOOK ordinary to the
//! classifier but name a secret file on a real filesystem (bead E027;
//! invariant I38; risk R82).
//!
//! E027 already ships the headline acceptance — seed secret and denied
//! paths among ordinary sources, and the uploaded set contains not one
//! of them — plus the structural rules: `.gitignore` is not a parameter
//! and cannot be consulted even by mistake, symlink and bind escapes
//! and device nodes dominate configuration, and the declared secret
//! capability is the only override that stands and still never uploads.
//! None of that is redone here.
//!
//! What every one of those cases has in common is that the path is
//! spelled exactly the way the built-in seed set spells it: absolute,
//! and lower case. The seed set is matched as raw bytes, so those two
//! incidental properties of the fixtures were load-bearing:
//!
//! - **Case.** `SECRET_LOCATION_PATTERNS` are lower case and the match
//!   was byte-exact, but the filesystems this has to protect on are
//!   not. On macOS APFS and on Windows, `.ENV` and `.env` are THE SAME
//!   FILE — so a capture that enumerated it under the upper-case
//!   spelling classified a credential as an ordinary build input and
//!   uploaded it. On Linux they are different files, but a file named
//!   `.ENV` is a secret there too, and the direction to err in is
//!   denial: a false positive costs an action its remote execution, a
//!   false negative ships a credential off the machine.
//!
//! - **Anchoring.** Five patterns begin with `/` so they match a path
//!   COMPONENT rather than any substring — `/.env` denies `ws/.env`
//!   while leaving `app.environment` alone. Nothing precedes the first
//!   component of a RELATIVE path, so a bare `.env` matched none of
//!   them and uploaded.
//!
//! These are evasions by accident, not by construction — nobody has to
//! be attacking for a capture to enumerate a path in either shape.

use rabs_sandbox::source_capture::{
    CaptureDecision, PathShape, SourceCapturePolicy, classify_path, partition_capture,
};

/// Every spelling of a secret path that must be refused, paired with
/// why it is not merely a hypothetical.
const MUST_DENY: &[(&[u8], &str)] = &[
    (
        b"/__rabs/workspace/.ENV",
        "upper case, same file on APFS/NTFS",
    ),
    (b"/__rabs/workspace/.Env", "mixed case"),
    (b"/__rabs/workspace/.env.PRODUCTION", "upper-case suffix"),
    (b"/home/u/.ssh/ID_RSA", "upper-case private key"),
    (b"/home/u/.ssh/Id_Ed25519", "mixed-case private key"),
    (b"/__rabs/workspace/signing.PEM", "upper-case key format"),
    (b"/__rabs/workspace/store.P12", "upper-case key format"),
    (b"/__rabs/workspace/release.KeyStore", "mixed-case keystore"),
    (b"/home/u/.AWS/credentials", "upper-case cloud creds"),
    (b"/home/u/.NETRC", "upper-case netrc"),
    (b"/home/u/.gnupg/SECRING.gpg", "upper-case signing material"),
    (b".env", "relative: nothing precedes the first component"),
    (b".env.production", "relative with suffix"),
    (b".netrc", "relative netrc"),
];

/// Spellings that must stay ordinary build inputs. Without these the
/// suite could be satisfied by denying everything, which would be a
/// worse bug than the one it is guarding.
const MUST_ALLOW: &[&[u8]] = &[
    b"/__rabs/workspace/src/lib.rs",
    b"/__rabs/workspace/build.rs",
    b"/__rabs/workspace/src/environment.rs",
    b"/__rabs/workspace/app.environment",
    b"/__rabs/workspace/docs/PEMDAS.md",
    b"src/lib.rs",
    b"build.rs",
];

#[test]
fn t027_secret_locations_are_denied_however_they_are_spelled() {
    for (path, why) in MUST_DENY {
        assert_eq!(
            classify_path(path, PathShape::REGULAR, None),
            SourceCapturePolicy::Denied,
            "{} ({why}) classified as uploadable: the built-in secret seed set is \
             matched as raw bytes, so a spelling the fixtures never used walks past it",
            String::from_utf8_lossy(path)
        );
    }
}

#[test]
fn t027_the_denial_rule_still_admits_ordinary_sources() {
    // The other half, and the reason the half above means anything: a
    // classifier that denied everything would satisfy it while making
    // remote execution impossible.
    for path in MUST_ALLOW {
        assert_eq!(
            classify_path(path, PathShape::REGULAR, None),
            SourceCapturePolicy::BuildInputAllowed,
            "{} must remain an ordinary build input",
            String::from_utf8_lossy(path)
        );
    }
}

#[test]
fn t027_no_spelling_of_a_secret_reaches_the_uploaded_set() {
    // E027's acceptance, re-run over the spellings its own fixtures did
    // not use. `partition_capture` is what the capture path actually
    // calls, so proving `classify_path` alone would leave the question
    // of whether the partition agrees with it.
    let mut discovered: Vec<(Vec<u8>, PathShape, Option<SourceCapturePolicy>)> = Vec::new();
    for (path, _) in MUST_DENY {
        discovered.push(((*path).to_vec(), PathShape::REGULAR, None));
    }
    for path in MUST_ALLOW {
        discovered.push(((*path).to_vec(), PathShape::REGULAR, None));
    }

    let CaptureDecision {
        uploaded,
        edge_private_receipt,
    } = partition_capture(&discovered);

    for (path, why) in MUST_DENY {
        assert!(
            !uploaded.contains(&(*path).to_vec()),
            "{} ({why}) reached the UPLOADED set",
            String::from_utf8_lossy(path)
        );
    }
    assert_eq!(
        uploaded,
        MUST_ALLOW
            .iter()
            .map(|p| (*p).to_vec())
            .collect::<Vec<Vec<u8>>>(),
        "exactly the ordinary sources upload, in discovery order"
    );
    assert_eq!(
        edge_private_receipt.len(),
        MUST_DENY.len(),
        "every denied observation must land in the edge-private receipt"
    );
}

#[test]
fn t027_a_case_variant_secret_is_not_rescued_by_weaker_configuration() {
    // E027's rule is that a built-in secret location is denied even when
    // the project configured something weaker, and that the declared
    // secret capability is the only override that stands — and that it
    // still never uploads. That rule has to survive the spelling too,
    // or a project could launder a credential past it by configuring
    // the upper-case name as an ordinary input.
    let path = b"/__rabs/workspace/.ENV";
    for weaker in [
        SourceCapturePolicy::BuildInputAllowed,
        SourceCapturePolicy::LocalOnly,
        SourceCapturePolicy::ExplicitOperatorApproval,
    ] {
        assert_eq!(
            classify_path(path, PathShape::REGULAR, Some(weaker)),
            SourceCapturePolicy::Denied,
            "configuring {weaker:?} must not downgrade a built-in secret location"
        );
    }
    assert_eq!(
        classify_path(
            path,
            PathShape::REGULAR,
            Some(SourceCapturePolicy::SecretCapability)
        ),
        SourceCapturePolicy::SecretCapability,
        "the declared capability route is the one override that stands"
    );
    // And it is still not an upload.
    let decision = partition_capture(&[(
        path.to_vec(),
        PathShape::REGULAR,
        Some(SourceCapturePolicy::SecretCapability),
    )]);
    assert!(
        decision.uploaded.is_empty(),
        "the capability route must never put a secret in the uploaded set"
    );
}

#[test]
fn t027_structural_refusal_still_dominates_every_spelling() {
    // Shape beats everything, including the question of whether the
    // name looked secret. An upper-case ordinary source that escapes
    // the closure is still denied.
    let escaping = PathShape {
        escapes_closure: true,
        special_node: false,
        unrelated_ancestor: false,
    };
    assert_eq!(
        classify_path(
            b"/__rabs/workspace/SRC/LIB.RS",
            escaping,
            Some(SourceCapturePolicy::BuildInputAllowed)
        ),
        SourceCapturePolicy::Denied
    );
}
