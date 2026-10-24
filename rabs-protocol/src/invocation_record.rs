//! The invocation-record schema for the record/replay corpus (bead B001).
//!
//! Every intercepted tool invocation becomes one record. The corpus these
//! records form is simultaneously: benchmark input, shadow-verification
//! input, regression suite, key-stability study, scheduler training data,
//! and launch evidence (plan Part XX §139) — which is why the schema is
//! versioned in the A005 registry and privacy-hardened from day one:
//!
//! - **Digests, not contents** (bead B004): source bytes never enter a
//!   record; argv/env are carried as correlation digests plus REDACTED
//!   presentation forms (A007 library applied at construction — a caller
//!   cannot construct a record with unredacted argv).
//! - **Byte-exact identity survives**: the digests are computed over the
//!   raw bytes (A019), so non-UTF8 argv correlates exactly even though the
//!   human-readable field is escaped+redacted.
//! - **Signal vs exit is preserved** (mirrors C008/R94): a signaled tool is
//!   recorded as signaled, never flattened into an exit code.
//!
//! Correlation digests are FNV-based (`redaction::correlation_hash`) until
//! F034's typed SHA-256 lands; they are correlation aids, not authoritative
//! identities, and the field names say so.

use crate::raw_bytes::RawBytes;
use crate::redaction::{correlation_hash, redact_argv, redact_env, redact_path};

/// Which tool the record captures (plan §140 context list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum ToolKind {
    Rustc,
    Rustdoc,
    Linker,
    BuildScriptCompile,
    BuildScriptRun,
    NativeCc,
    NativeCxx,
    NativeAr,
    CargoWholeCommand,
    Nextest,
}

impl ToolKind {
    /// All ten required B003 tool contexts (`plan §140`).
    pub const ALL: [Self; 10] = [
        Self::Rustc,
        Self::Rustdoc,
        Self::Linker,
        Self::BuildScriptCompile,
        Self::BuildScriptRun,
        Self::NativeCc,
        Self::NativeCxx,
        Self::NativeAr,
        Self::CargoWholeCommand,
        Self::Nextest,
    ];

    /// Stable canonical string representation used in B002/B010 NDJSON lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rustc => "Rustc",
            Self::Rustdoc => "Rustdoc",
            Self::Linker => "Linker",
            Self::BuildScriptCompile => "BuildScriptCompile",
            Self::BuildScriptRun => "BuildScriptRun",
            Self::NativeCc => "NativeCc",
            Self::NativeCxx => "NativeCxx",
            Self::NativeAr => "NativeAr",
            Self::CargoWholeCommand => "CargoWholeCommand",
            Self::Nextest => "Nextest",
        }
    }

    /// Parse a canonical or lowercase tool-kind name.
    #[must_use]
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "Rustc" | "rustc" => Some(Self::Rustc),
            "Rustdoc" | "rustdoc" => Some(Self::Rustdoc),
            "Linker" | "linker" => Some(Self::Linker),
            "BuildScriptCompile" | "build_script_compile" => Some(Self::BuildScriptCompile),
            "BuildScriptRun" | "build_script_run" => Some(Self::BuildScriptRun),
            "NativeCc" | "native_cc" => Some(Self::NativeCc),
            "NativeCxx" | "native_cxx" => Some(Self::NativeCxx),
            "NativeAr" | "native_ar" => Some(Self::NativeAr),
            "CargoWholeCommand" | "cargo_whole_command" => Some(Self::CargoWholeCommand),
            "Nextest" | "nextest" => Some(Self::Nextest),
            _ => None,
        }
    }
}

/// Deterministically classify an intercepted invocation across all ten B003
/// tool contexts (`rustc`, `rustdoc`, `linker`, `build.rs` compile/run,
/// `cc`/`cxx`/`ar`, `cargo`, `nextest`).
#[must_use]
pub fn classify_tool_context(argv: &[RawBytes], env: &[(RawBytes, RawBytes)]) -> Option<ToolKind> {
    let first = argv.first()?.escaped();
    let bin = first.rsplit('/').next().unwrap_or(first.as_str());
    let args_escaped: Vec<String> = argv.iter().skip(1).map(RawBytes::escaped).collect();
    let has_env = |key: &str, expected: Option<&str>| -> bool {
        env.iter()
            .any(|(k, v)| k.escaped() == key && expected.is_none_or(|exp| v.escaped() == exp))
    };

    // 1. rustdoc binary
    if bin == "rustdoc" {
        return Some(ToolKind::Rustdoc);
    }

    // 2. rustc (either build-script compile or regular crate compile)
    if bin == "rustc" {
        let is_build_script = args_escaped
            .windows(2)
            .any(|w| w[0] == "--crate-name" && w[1] == "build_script_build")
            || args_escaped
                .iter()
                .any(|a| a == "--crate-name=build_script_build")
            || has_env("CARGO_CRATE_NAME", Some("build_script_build"));
        if is_build_script {
            return Some(ToolKind::BuildScriptCompile);
        }
        return Some(ToolKind::Rustc);
    }

    // 3. build-script-build execution
    if bin.starts_with("build-script-")
        || bin.starts_with("build_script_")
        || (first.contains("/build/")
            && has_env("OUT_DIR", None)
            && has_env("CARGO_MANIFEST_DIR", None))
    {
        return Some(ToolKind::BuildScriptRun);
    }

    // 4. Dedicated linkers
    if matches!(
        bin,
        "ld" | "ld.lld" | "lld" | "rust-lld" | "wild" | "mold" | "collect2"
    ) {
        return Some(ToolKind::Linker);
    }

    // 5. Archive tools
    if matches!(bin, "ar" | "llvm-ar" | "gcc-ar" | "ranlib" | "llvm-ranlib") {
        return Some(ToolKind::NativeAr);
    }

    // 6. C / C++ compilers vs driver-invoked linker
    let is_cc = matches!(bin, "cc" | "gcc" | "clang");
    let is_cxx = matches!(bin, "c++" | "g++" | "clang++");
    if is_cc || is_cxx {
        let has_compile_only = args_escaped
            .iter()
            .any(|a| a == "-c" || a == "-S" || a == "-E");
        let has_linker_inputs = args_escaped.iter().any(|a| {
            a.starts_with("-Wl,")
                || a.ends_with(".rlib")
                || a.ends_with(".o")
                || a.ends_with(".a")
                || a.contains("symbols.o")
        });
        if !has_compile_only && has_linker_inputs {
            return Some(ToolKind::Linker);
        }
        return Some(if is_cxx {
            ToolKind::NativeCxx
        } else {
            ToolKind::NativeCc
        });
    }

    // 7. nextest binary or cargo nextest subcommand
    if bin == "cargo-nextest" {
        return Some(ToolKind::Nextest);
    }
    if bin == "cargo" {
        let subcmd = args_escaped
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(String::as_str);
        return match subcmd {
            Some("nextest") => Some(ToolKind::Nextest),
            Some("doc" | "rustdoc") => Some(ToolKind::Rustdoc),
            Some(_) => Some(ToolKind::CargoWholeCommand),
            None => None,
        };
    }

    None
}

/// Normalized process outcome, preserving signal-vs-exit semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizedOutcome {
    /// Normal exit with a status code.
    Exited(i32),
    /// Terminated by a signal (Unix signal number).
    Signaled(i32),
}

/// One recorded invocation. Construct via [`InvocationRecord::capture`],
/// which applies redaction — the raw argv/env never enter the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationRecord {
    /// Schema version (registered as `rabs.invocation-record` in the A005
    /// registry).
    pub schema_version: u32,
    /// The tool.
    pub tool: ToolKind,
    /// Correlation digest over the raw argv bytes (exactness without
    /// content retention; correlation-grade until F034).
    pub argv_correlation: u64,
    /// Redacted, escaped argv for humans (A007 applied; secrets absent).
    pub argv_redacted: Vec<String>,
    /// Correlation digest over the raw environment bytes.
    pub env_correlation: u64,
    /// Redacted `NAME=value` lines (secret values replaced, names kept).
    pub env_redacted: Vec<String>,
    /// Redacted real working directory (home → `~`).
    pub cwd_redacted: String,
    /// Outcome with signal-vs-exit preserved.
    pub outcome: NormalizedOutcome,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// Current schema version.
pub const INVOCATION_RECORD_VERSION: u32 = 1;

impl InvocationRecord {
    /// Classify the tool context from raw `argv`/`env` (bead B003) and capture
    /// a redacted [`InvocationRecord`] if the invocation belongs to one of the
    /// ten RABS tool contexts.
    #[must_use]
    pub fn capture_classified(
        argv: &[RawBytes],
        env: &[(RawBytes, RawBytes)],
        cwd: &RawBytes,
        home: &str,
        outcome: NormalizedOutcome,
        duration_ms: u64,
    ) -> Option<Self> {
        let tool = classify_tool_context(argv, env)?;
        Some(Self::capture(
            tool,
            argv,
            env,
            cwd,
            home,
            outcome,
            duration_ms,
        ))
    }

    /// Capture a record from raw observations, applying redaction and
    /// digesting the raw bytes. This is the ONLY constructor on purpose.
    #[must_use]
    pub fn capture(
        tool: ToolKind,
        argv: &[RawBytes],
        env: &[(RawBytes, RawBytes)],
        cwd: &RawBytes,
        home: &str,
        outcome: NormalizedOutcome,
        duration_ms: u64,
    ) -> Self {
        // Correlation digests over the RAW bytes (byte-exact identity).
        let mut argv_bytes = Vec::new();
        for a in argv {
            argv_bytes.extend_from_slice(a.as_bytes());
            argv_bytes.push(0);
        }
        let mut env_bytes = Vec::new();
        for (k, v) in env {
            env_bytes.extend_from_slice(k.as_bytes());
            env_bytes.push(b'=');
            env_bytes.extend_from_slice(v.as_bytes());
            env_bytes.push(0);
        }
        // Redacted presentation forms (escaped first: presentation-only).
        let argv_escaped: Vec<String> = argv.iter().map(RawBytes::escaped).collect();
        let argv_redacted = redact_argv(&argv_escaped);
        let env_redacted = env
            .iter()
            .map(|(k, v)| redact_env(&k.escaped(), &v.escaped()))
            .collect();
        Self {
            schema_version: INVOCATION_RECORD_VERSION,
            tool,
            argv_correlation: correlation_hash(&argv_bytes),
            argv_redacted,
            env_correlation: correlation_hash(&env_bytes),
            env_redacted,
            cwd_redacted: redact_path(&cwd.escaped(), home),
            outcome,
            duration_ms,
        }
    }
}

/// Content-retention policy for corpus storage (bead B004): digests-only
/// is the default and the only unconditional mode; retaining actual bytes
/// requires an explicit incident reference and expires with it (corpus
/// policy §1/§2, docs/rabs-corpus-policy.md).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ContentRetention {
    /// Only correlation digests and redacted presentation forms persist.
    #[default]
    DigestsOnly,
    /// Bytes retained for one named incident; deleted when it closes.
    ExplicitIncidentRetention {
        /// The incident that justifies retention (its closure expires this).
        incident_id: u64,
    },
}

impl InvocationRecord {
    /// Exhaustive field audit (bead B004): destructures every field and
    /// returns the names of fields that carry free-form/raw content.
    /// Adding a field to the record without classifying it here is a
    /// compile error; the audit test asserts the list stays empty.
    #[must_use]
    pub fn raw_content_fields(&self) -> Vec<&'static str> {
        let Self {
            schema_version: _,   // number
            tool: _,             // enum
            argv_correlation: _, // digest
            argv_redacted: _,    // redacted presentation (A007-processed)
            env_correlation: _,  // digest
            env_redacted: _,     // redacted presentation (A007-processed)
            cwd_redacted: _,     // redacted presentation (A007-processed)
            outcome: _,          // enum
            duration_ms: _,      // number
        } = self;
        // Every field above is a digest, number, enum, or A007-redacted
        // presentation form. No raw-content field exists.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with(argv: &[&str], env: &[(&str, &str)]) -> InvocationRecord {
        let argv: Vec<RawBytes> = argv.iter().map(|s| RawBytes::from(*s)).collect();
        let env: Vec<(RawBytes, RawBytes)> = env
            .iter()
            .map(|(k, v)| (RawBytes::from(*k), RawBytes::from(*v)))
            .collect();
        InvocationRecord::capture(
            ToolKind::Rustc,
            &argv,
            &env,
            &RawBytes::from("/Users/alice/work/repo"),
            "/Users/alice",
            NormalizedOutcome::Exited(0),
            1234,
        )
    }

    #[test]
    fn secrets_cannot_enter_a_record() {
        let r = record_with(
            &["cargo", "publish", "--token=tok_live_supersecret"],
            &[
                ("CARGO_REGISTRY_TOKEN", "tok_live_supersecret"),
                ("RUSTFLAGS", "-Cdebuginfo=1"),
            ],
        );
        let dump = format!("{r:?}");
        assert!(
            !dump.contains("tok_live_supersecret"),
            "secret leaked into the record: {dump}"
        );
        // Names and non-secrets survive for diagnosis.
        assert!(dump.contains("CARGO_REGISTRY_TOKEN"));
        assert!(dump.contains("RUSTFLAGS=-Cdebuginfo=1"));
        // Home is tilde-redacted.
        assert_eq!(r.cwd_redacted, "~/work/repo");
    }

    #[test]
    fn correlation_is_byte_exact_even_for_non_utf8() {
        let latin1 = [
            RawBytes::from(&b"rustc"[..]),
            RawBytes::from(&b"caf\xE9.rs"[..]),
        ];
        let utf8 = [RawBytes::from(&b"rustc"[..]), RawBytes::from("café.rs")];
        let empty_env: [(RawBytes, RawBytes); 0] = [];
        let ra = InvocationRecord::capture(
            ToolKind::Rustc,
            &latin1,
            &empty_env,
            &RawBytes::from("/w"),
            "",
            NormalizedOutcome::Exited(0),
            1,
        );
        let rb = InvocationRecord::capture(
            ToolKind::Rustc,
            &utf8,
            &empty_env,
            &RawBytes::from("/w"),
            "",
            NormalizedOutcome::Exited(0),
            1,
        );
        assert_ne!(
            ra.argv_correlation, rb.argv_correlation,
            "lossy-equivalent spellings must correlate differently (A019)"
        );
    }

    #[test]
    fn argv_element_boundaries_matter() {
        // ["ab","c"] and ["a","bc"] must not correlate equal (separator).
        let x = [RawBytes::from("ab"), RawBytes::from("c")];
        let y = [RawBytes::from("a"), RawBytes::from("bc")];
        let empty_env: [(RawBytes, RawBytes); 0] = [];
        let rx = InvocationRecord::capture(
            ToolKind::Linker,
            &x,
            &empty_env,
            &RawBytes::from("/w"),
            "",
            NormalizedOutcome::Exited(0),
            1,
        );
        let ry = InvocationRecord::capture(
            ToolKind::Linker,
            &y,
            &empty_env,
            &RawBytes::from("/w"),
            "",
            NormalizedOutcome::Exited(0),
            1,
        );
        assert_ne!(rx.argv_correlation, ry.argv_correlation);
    }

    #[test]
    fn signal_termination_is_not_an_exit_code() {
        assert_ne!(
            NormalizedOutcome::Signaled(9),
            NormalizedOutcome::Exited(137),
            "128+N flattening is exactly what the schema must prevent (R94)"
        );
    }

    #[test]
    fn records_carry_digests_only_no_raw_content_fields() {
        // B004: the exhaustive field audit must report zero raw-content
        // fields — the schema structurally cannot retain source bytes.
        let r = record_with(&["rustc", "lib.rs"], &[("RUSTFLAGS", "-O")]);
        assert!(
            r.raw_content_fields().is_empty(),
            "raw-content fields present: {:?}",
            r.raw_content_fields()
        );
    }

    #[test]
    fn content_retention_defaults_to_digests_only_and_bytes_need_an_incident() {
        assert_eq!(ContentRetention::default(), ContentRetention::DigestsOnly);
        // The only other mode NAMES the incident that justifies it — there
        // is no unconditional keep-bytes mode to reach for.
        let r = ContentRetention::ExplicitIncidentRetention { incident_id: 42 };
        assert_ne!(r, ContentRetention::DigestsOnly);
    }

    #[test]
    fn schema_is_registered() {
        use crate::schema_registry::{SchemaDomain, lookup};
        let entry = lookup(SchemaDomain::Protocol, "rabs.invocation-record")
            .expect("invocation-record schema must be registered (A005)");
        assert_eq!(entry.version, INVOCATION_RECORD_VERSION);
    }

    #[test]
    fn b003_classifies_and_captures_all_ten_tool_contexts() {
        type ToolCase<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], ToolKind);
        let cases: &[ToolCase<'_>] = &[
            (
                &["rustc", "--crate-name", "rabs_key", "src/lib.rs"],
                &[],
                ToolKind::Rustc,
            ),
            (
                &["rustdoc", "--crate-name", "rabs_key", "src/lib.rs"],
                &[],
                ToolKind::Rustdoc,
            ),
            (
                &[
                    "cc",
                    "-Wl,--as-needed",
                    "target/debug/deps/rabs.o",
                    "-o",
                    "target/debug/rabs",
                ],
                &[],
                ToolKind::Linker,
            ),
            (
                &["rustc", "--crate-name", "build_script_build", "build.rs"],
                &[],
                ToolKind::BuildScriptCompile,
            ),
            (
                &["target/debug/build/zstd-sys-123/build-script-build"],
                &[
                    ("OUT_DIR", "/tmp/out"),
                    ("CARGO_MANIFEST_DIR", "/work/zstd-sys"),
                ],
                ToolKind::BuildScriptRun,
            ),
            (
                &["clang", "-c", "-O2", "src/compress.c", "-o", "compress.o"],
                &[],
                ToolKind::NativeCc,
            ),
            (
                &["clang++", "-c", "-O2", "src/bridge.cc", "-o", "bridge.o"],
                &[],
                ToolKind::NativeCxx,
            ),
            (
                &["llvm-ar", "crs", "libzstd.a", "compress.o"],
                &[],
                ToolKind::NativeAr,
            ),
            (
                &["cargo", "check", "--workspace"],
                &[],
                ToolKind::CargoWholeCommand,
            ),
            (
                &["cargo", "nextest", "run", "--workspace"],
                &[],
                ToolKind::Nextest,
            ),
        ];

        let mut seen = std::collections::BTreeSet::new();
        for (argv_strs, env_strs, expected) in cases {
            let argv: Vec<RawBytes> = argv_strs.iter().map(|s| RawBytes::from(*s)).collect();
            let env: Vec<(RawBytes, RawBytes)> = env_strs
                .iter()
                .map(|(k, v)| (RawBytes::from(*k), RawBytes::from(*v)))
                .collect();
            let rec = InvocationRecord::capture_classified(
                &argv,
                &env,
                &RawBytes::from("/Users/alice/work/repo"),
                "/Users/alice",
                NormalizedOutcome::Exited(0),
                42,
            )
            .expect("must classify tool context");
            assert_eq!(rec.tool, *expected);
            assert_eq!(ToolKind::from_str_name(rec.tool.as_str()), Some(*expected));
            seen.insert(rec.tool);
        }
        assert_eq!(seen.len(), ToolKind::ALL.len());
    }
}
