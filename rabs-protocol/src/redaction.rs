//! Shared redaction library and data-classification policy (bead A007).
//!
//! One library, used by every surface that persists or transmits
//! observations — decision receipts, logs, key breakdowns, failure bundles,
//! telemetry, test-harness structured logs (bead T053) — so secret hygiene
//! is a property of the pipeline, not a per-call-site discipline
//! (invariants I26/I38; one forgotten call site must not leak credentials
//! into durable evidence).
//!
//! ## Policy (binding)
//!
//! - **Raw secrets never appear anywhere.** Secret-classified values are
//!   replaced by `[REDACTED:<why>]`; names/keys are preserved so operators
//!   can still see *what* was set.
//! - **Source contents are not logged by default**; only digests and
//!   bounded excerpts under explicit policy.
//! - **Home/worktree paths** become `~`-relative or labeled forms; raw
//!   user homes never enter durable evidence.
//! - **Bounded excerpts only**: anything free-form is truncated with an
//!   explicit marker.
//! - Where a raw value cannot be logged, a **correlation hash** may be
//!   retained. It is FNV-1a — a correlation aid, NOT a cryptographic
//!   commitment (authoritative digests are typed SHA-256, bead F034) and
//!   deliberately unsuitable for secret values whose search space is small.
//!
//! Secret scanners are advisory defense-in-depth: heuristics here cannot
//! prove absence of secrets in arbitrary bytes (plan §31.1). Fail toward
//! redaction on ambiguity.

/// Classification of a datum for logging/persistence purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass {
    /// Safe to log verbatim.
    Public,
    /// Redact the value, keep the name (secrets/credentials).
    SecretSensitive,
    /// Rewrite to a home-relative/labeled form before logging.
    PathSensitive,
    /// Never logged by default; digest + bounded excerpt only.
    SourceContent,
}

/// Marker substituted for secret-classified values.
pub const REDACTED: &str = "[REDACTED:secret]";

/// Marker appended when an excerpt was truncated.
pub const TRUNCATED: &str = "…[truncated]";

/// Case-insensitive name fragments that classify an environment variable or
/// flag name as secret-bearing. Deliberately broad: false positives cost a
/// redacted log line; false negatives cost a credential leak.
const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "API_KEY",
    "APIKEY",
    "AUTH",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SESSION_KEY",
    "SIGNING",
    "COOKIE",
];

fn ascii_upper(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_uppercase()).collect()
}

/// Classify an environment-variable (or flag) NAME.
#[must_use]
pub fn classify_env_key(name: &str) -> DataClass {
    let upper = ascii_upper(name);
    if SECRET_NAME_FRAGMENTS.iter().any(|f| upper.contains(f)) {
        DataClass::SecretSensitive
    } else {
        DataClass::Public
    }
}

/// Render one environment pair for logging: secret values are replaced,
/// names always survive.
#[must_use]
pub fn redact_env(name: &str, value: &str) -> String {
    match classify_env_key(name) {
        DataClass::SecretSensitive => format!("{name}={REDACTED}"),
        _ => format!("{name}={value}"),
    }
}

/// Rewrite an absolute path for logging: the user's home prefix becomes
/// `~`, so raw homes never enter durable evidence. Non-home paths pass
/// through (worktree→virtual mapping is the edge's path-translation job;
/// this is the last-resort log hygiene layer).
#[must_use]
pub fn redact_path(path: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return path.to_string();
    }
    if let Some(rest) = path.strip_prefix(home) {
        if rest.is_empty() {
            return "~".to_string();
        }
        if let Some(stripped) = rest.strip_prefix('/') {
            return format!("~/{stripped}");
        }
    }
    path.to_string()
}

/// Redact an argv for logging:
/// - `--flag=value` where the flag name is secret-classified → value redacted;
/// - a standalone secret-classified flag redacts the FOLLOWING argument
///   (`--token abc` → `--token [REDACTED:secret]`);
/// - URL userinfo passwords (`scheme://user:pass@host`) are scrubbed.
#[must_use]
pub fn redact_argv<S: AsRef<str>>(argv: &[S]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    for arg in argv {
        let arg = arg.as_ref();
        if redact_next {
            out.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }
        if let Some((flag, _value)) = arg.split_once('=') {
            if classify_env_key(flag.trim_start_matches('-')) == DataClass::SecretSensitive {
                out.push(format!("{flag}={REDACTED}"));
                continue;
            }
        } else if arg.starts_with('-')
            && classify_env_key(arg.trim_start_matches('-')) == DataClass::SecretSensitive
        {
            out.push(arg.to_string());
            redact_next = true;
            continue;
        }
        out.push(scrub_url_userinfo(arg));
    }
    out
}

/// Scrub the password portion of URL userinfo: `scheme://u:p@h` → `scheme://u:[REDACTED:secret]@h`.
#[must_use]
pub fn scrub_url_userinfo(s: &str) -> String {
    let Some(scheme_end) = s.find("://") else {
        return s.to_string();
    };
    let after_scheme = &s[scheme_end + 3..];
    let Some(at) = after_scheme.find('@') else {
        return s.to_string();
    };
    let userinfo = &after_scheme[..at];
    let Some(colon) = userinfo.find(':') else {
        return s.to_string();
    };
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..scheme_end + 3]);
    out.push_str(&userinfo[..colon]);
    out.push(':');
    out.push_str(REDACTED);
    out.push_str(&after_scheme[at..]);
    out
}

/// Produce a bounded excerpt of free-form text: at most `max_chars`
/// characters, with an explicit truncation marker when shortened.
#[must_use]
pub fn bounded_excerpt(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let cut: String = text.chars().take(max_chars).collect();
    format!("{cut}{TRUNCATED}")
}

/// FNV-1a correlation hash for values that cannot be logged raw.
///
/// NOT cryptographic, NOT for secrets with small search spaces, NOT an
/// authoritative digest (those are typed SHA-256, bead F034) — this exists
/// so two receipts can say "same unloggable value" without carrying it.
#[must_use]
pub fn correlation_hash(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_env_names_are_classified_and_values_redacted() {
        for name in [
            "CARGO_REGISTRY_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "MY_API_KEY",
            "DB_PASSWORD",
            "ssh_passphrase",
            "GITHUB_AUTH",
        ] {
            assert_eq!(
                classify_env_key(name),
                DataClass::SecretSensitive,
                "{name} must classify secret"
            );
            let line = redact_env(name, "hunter2");
            assert!(!line.contains("hunter2"), "value leaked for {name}: {line}");
            assert!(line.contains(name), "name must survive for {name}");
        }
    }

    #[test]
    fn ordinary_env_passes_through_unchanged() {
        // The paired permitted case: redaction must not destroy signal.
        for name in ["RUSTFLAGS", "PATH", "CARGO_HOME", "TERM"] {
            assert_eq!(classify_env_key(name), DataClass::Public);
        }
        assert_eq!(
            redact_env("RUSTFLAGS", "-Cdebuginfo=1"),
            "RUSTFLAGS=-Cdebuginfo=1"
        );
    }

    #[test]
    fn argv_credentials_are_redacted_in_both_shapes() {
        let argv = [
            "publish",
            "--token=tok_live_abcdef",
            "--registry-token",
            "tok_live_zzz",
            "--jobs=4",
        ];
        let out = redact_argv(&argv);
        let joined = out.join(" ");
        assert!(
            !joined.contains("tok_live_abcdef"),
            "inline value leaked: {joined}"
        );
        assert!(
            !joined.contains("tok_live_zzz"),
            "following value leaked: {joined}"
        );
        assert!(
            joined.contains("--jobs=4"),
            "non-secret flag mangled: {joined}"
        );
        assert!(joined.contains("--token=[REDACTED:secret]"));
    }

    #[test]
    fn url_userinfo_password_is_scrubbed() {
        let out = scrub_url_userinfo("https://alice:s3cr3t@registry.example/path");
        assert!(!out.contains("s3cr3t"), "url password leaked: {out}");
        assert!(out.contains("alice"), "username should survive: {out}");
        // Paired permitted cases: no userinfo, no colon → untouched.
        assert_eq!(
            scrub_url_userinfo("https://registry.example/path"),
            "https://registry.example/path"
        );
        assert_eq!(
            scrub_url_userinfo("https://alice@registry.example"),
            "https://alice@registry.example"
        );
    }

    #[test]
    fn home_paths_become_tilde_relative() {
        assert_eq!(
            redact_path("/Users/alice/work/repo/src/lib.rs", "/Users/alice"),
            "~/work/repo/src/lib.rs"
        );
        assert_eq!(redact_path("/Users/alice", "/Users/alice"), "~");
        // Prefix must match on a path boundary: /Users/alicetwo is NOT home.
        assert_eq!(
            redact_path("/Users/alicetwo/x", "/Users/alice"),
            "/Users/alicetwo/x"
        );
        assert_eq!(redact_path("/opt/thing", "/Users/alice"), "/opt/thing");
    }

    #[test]
    fn excerpts_are_bounded_with_marker() {
        let long = "x".repeat(100);
        let cut = bounded_excerpt(&long, 10);
        assert!(cut.starts_with("xxxxxxxxxx"));
        assert!(cut.ends_with(TRUNCATED));
        assert_eq!(bounded_excerpt("short", 10), "short");
    }

    #[test]
    fn correlation_hash_is_stable_and_discriminating() {
        assert_eq!(correlation_hash(b"abc"), correlation_hash(b"abc"));
        assert_ne!(correlation_hash(b"abc"), correlation_hash(b"abd"));
    }
}
