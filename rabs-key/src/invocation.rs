//! Normalized rustc invocation parser (bead F003; plan §61–§66; risks
//! R2/R3/R8).
//!
//! Turns a raw compiler-wrapper argv into a [`NormalizedRustcInvocation`]:
//! the semantic argument model whose canonical bytes feed the action key
//! (F012). Soundness rules, in priority order:
//!
//! 1. **Unknown flags are PRESERVED, never dropped.** Exclusion is an
//!    explicit allowlist of known-volatile presentation flags
//!    (`--color`, `--diagnostic-width`); anything unrecognized lands in
//!    `passthrough` in original order and thus keys conservatively (a
//!    spurious miss beats a false hit — the plan's cardinal rule).
//! 2. **The wrapper chain is decoded, not keyed.** Leading argv elements
//!    up to the real compiler (`RUSTC_WRAPPER` protocol: wrappers
//!    prepend themselves) are recorded diagnostically; wrapper-only
//!    flags are stripped. Compiler *identity* enters the key through the
//!    toolchain fingerprint (F002), never through the local spelling of
//!    the rustc path.
//! 3. **Semantically meaningful order is preserved** within each group
//!    (`-L` search order, `--cfg` order, codegen flag order) — rustc
//!    honors order for several of these, so reordering could alias two
//!    different builds.
//! 4. **Stdin compiles carry the content digest.** A `-` source without
//!    a stdin digest is a parse error, not a keyable invocation.
//!
//! Path-bearing fields (`out_dir`, extern paths, `-L` paths, the source
//! path) are captured **as given**; callers must run them through the
//! F004 canonical execroot mapping before this value is keyed — the
//! bead-F012 pipeline enforces that ordering. Socket paths, request/
//! subscriber/attempt/worker IDs, and jobserver descriptors never appear
//! in rustc argv (they travel in env/fd space and are excluded by the
//! env-policy bead F010), so their exclusion here is structural.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;

/// The compile source input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceInput {
    /// A path argument (virtualized later by F004).
    Path(String),
    /// Stdin (`-`) with the mandatory content digest.
    Stdin(TypedDigest),
}

/// One lint-level flag in original order (`-W`, `-A`, `-D`, `-F`,
/// `--warn`, … all normalize to these levels).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFlag {
    /// `warn` | `allow` | `deny` | `forbid` | `force-warn`.
    pub level: &'static str,
    /// The lint (or lint-group) name exactly as given.
    pub name: String,
}

/// The normalized invocation model.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizedRustcInvocation {
    /// Decoded wrapper chain basenames, outermost first (diagnostic
    /// only; never part of canonical bytes).
    pub wrapper_chain: Vec<String>,
    /// Wrapper-only flags stripped during chain decode (diagnostic).
    pub stripped_wrapper_flags: Vec<String>,
    /// The compiler argv\[0\] as given (diagnostic; identity is keyed
    /// via the F002 toolchain fingerprint instead).
    pub compiler_argv0: String,
    /// The source file, or stdin + digest.
    pub source: Option<SourceInput>,
    /// `--crate-name`.
    pub crate_name: Option<String>,
    /// `--crate-type` values in order (comma lists split).
    pub crate_types: Vec<String>,
    /// `--edition`.
    pub edition: Option<String>,
    /// `--target`.
    pub target: Option<String>,
    /// `--emit` values in order (comma lists split).
    pub emit: Vec<String>,
    /// `-C name[=value]` codegen flags in original order.
    pub codegen: Vec<(String, Option<String>)>,
    /// `-Z name[=value]` unstable flags in original order.
    pub unstable: Vec<(String, Option<String>)>,
    /// `--cfg` values in original order, EXCEPT `feature="…"` values.
    pub cfgs: Vec<String>,
    /// Feature names from `--cfg feature="…"` in original order.
    pub features: Vec<String>,
    /// Lint flags in original order (order decides precedence).
    pub lints: Vec<LintFlag>,
    /// `--cap-lints`.
    pub cap_lints: Option<String>,
    /// `--extern name[=path]` in original order.
    pub externs: Vec<(String, Option<String>)>,
    /// `-L [kind=]path` search paths in original order.
    pub lib_search: Vec<String>,
    /// `-l [kind=]name` native libraries in original order.
    pub native_libs: Vec<String>,
    /// `--out-dir` exactly as given (F004 virtualizes before keying).
    pub out_dir: Option<String>,
    /// Everything unrecognized, in original order (sound-by-inclusion).
    pub passthrough: Vec<String>,
    /// Known-volatile presentation flags that were dropped (`--color`,
    /// `--diagnostic-width`) — diagnostic record of the exclusion.
    pub excluded_presentation: Vec<String>,
}

/// Parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Empty argv.
    EmptyArgv,
    /// No plausible compiler found in the wrapper chain.
    NoCompilerInChain,
    /// Source is stdin (`-`) but no content digest was provided.
    StdinWithoutDigest,
    /// Two positional source arguments.
    MultipleSources(String, String),
}

/// Whether a path names a plausible rustc binary (chain decode only —
/// never a keying decision).
fn is_rustc_like(arg: &str) -> bool {
    let base = arg.rsplit(['/', '\\']).next().unwrap_or(arg);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    base == "rustc" || base == "clippy-driver" || base == "rustdoc"
}

/// Split `--flag=value` / `--flag value` style options.
fn take_value<I: Iterator<Item = String>>(
    arg: &str,
    long: &str,
    rest: &mut std::iter::Peekable<I>,
) -> Option<String> {
    if let Some(v) = arg.strip_prefix(long).and_then(|s| s.strip_prefix('=')) {
        return Some(v.to_owned());
    }
    if arg == long {
        return rest.next();
    }
    None
}

/// Short flag with attached or separate value: `-Copt-level=3` or
/// `-C opt-level=3`.
fn short_value<I: Iterator<Item = String>>(
    arg: &str,
    prefix: &str,
    rest: &mut std::iter::Peekable<I>,
) -> Option<String> {
    if arg == prefix {
        return rest.next();
    }
    arg.strip_prefix(prefix).map(str::to_owned)
}

/// Split a `name[=value]` pair.
fn name_value(s: &str) -> (String, Option<String>) {
    match s.split_once('=') {
        Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
        None => (s.to_owned(), None),
    }
}

/// Parse a raw wrapper-chain argv into the normalized model.
///
/// `stdin_digest` must be `Some` when (and only matters when) the
/// source argument is `-`.
#[allow(clippy::too_many_lines)]
pub fn parse(
    argv: &[String],
    stdin_digest: Option<TypedDigest>,
) -> Result<NormalizedRustcInvocation, ParseError> {
    if argv.is_empty() {
        return Err(ParseError::EmptyArgv);
    }
    let mut inv = NormalizedRustcInvocation::default();

    // Decode the wrapper chain: RUSTC_WRAPPER-protocol wrappers prepend
    // themselves, so the REAL compiler is the first rustc-like element;
    // non-flag elements before it are wrappers, flag elements before it
    // are wrapper-only flags (stripped, recorded).
    let compiler_pos = argv.iter().position(|a| is_rustc_like(a));
    let compiler_pos = match compiler_pos {
        Some(p) => p,
        // No rustc-like element anywhere: treat argv[0] as the compiler
        // only if it is not itself flag-shaped; otherwise fail.
        None if !argv[0].starts_with('-') => 0,
        None => return Err(ParseError::NoCompilerInChain),
    };
    for pre in &argv[..compiler_pos] {
        if pre.starts_with('-') {
            inv.stripped_wrapper_flags.push(pre.clone());
        } else {
            let base = pre.rsplit(['/', '\\']).next().unwrap_or(pre);
            inv.wrapper_chain.push(base.to_owned());
        }
    }
    inv.compiler_argv0 = argv[compiler_pos].clone();

    let mut rest = argv[compiler_pos + 1..].iter().cloned().peekable();
    while let Some(arg) = rest.next() {
        let a = arg.as_str();
        // Known-volatile presentation flags: the ONLY dropped surface.
        if a == "--color" || a.starts_with("--color=") {
            if a == "--color" {
                rest.next();
            }
            inv.excluded_presentation.push(arg);
            continue;
        }
        if a == "--diagnostic-width" || a.starts_with("--diagnostic-width=") {
            if a == "--diagnostic-width" {
                rest.next();
            }
            inv.excluded_presentation.push(arg);
            continue;
        }
        if let Some(v) = take_value(a, "--crate-name", &mut rest) {
            inv.crate_name = Some(v);
        } else if let Some(v) = take_value(a, "--crate-type", &mut rest) {
            inv.crate_types.extend(v.split(',').map(str::to_owned));
        } else if let Some(v) = take_value(a, "--edition", &mut rest) {
            inv.edition = Some(v);
        } else if let Some(v) = take_value(a, "--target", &mut rest) {
            inv.target = Some(v);
        } else if let Some(v) = take_value(a, "--emit", &mut rest) {
            inv.emit.extend(v.split(',').map(str::to_owned));
        } else if let Some(v) = take_value(a, "--out-dir", &mut rest) {
            inv.out_dir = Some(v);
        } else if let Some(v) = take_value(a, "--cap-lints", &mut rest) {
            inv.cap_lints = Some(v);
        } else if let Some(v) = take_value(a, "--cfg", &mut rest) {
            // `feature="name"` cfgs are the feature set; others are cfgs.
            if let Some(f) = v
                .strip_prefix("feature=\"")
                .and_then(|s| s.strip_suffix('"'))
            {
                inv.features.push(f.to_owned());
            } else {
                inv.cfgs.push(v);
            }
        } else if let Some(v) = take_value(a, "--extern", &mut rest) {
            inv.externs.push(name_value(&v));
        } else if let Some(v) =
            short_value(a, "-C", &mut rest).or_else(|| take_value(a, "--codegen", &mut rest))
        {
            inv.codegen.push(name_value(&v));
        } else if let Some(v) = short_value(a, "-Z", &mut rest) {
            inv.unstable.push(name_value(&v));
        } else if let Some(v) = short_value(a, "-L", &mut rest) {
            inv.lib_search.push(v);
        } else if let Some(v) = short_value(a, "-l", &mut rest) {
            inv.native_libs.push(v);
        } else if let Some(v) =
            short_value(a, "-W", &mut rest).or_else(|| take_value(a, "--warn", &mut rest))
        {
            inv.lints.push(LintFlag {
                level: "warn",
                name: v,
            });
        } else if let Some(v) =
            short_value(a, "-A", &mut rest).or_else(|| take_value(a, "--allow", &mut rest))
        {
            inv.lints.push(LintFlag {
                level: "allow",
                name: v,
            });
        } else if let Some(v) =
            short_value(a, "-D", &mut rest).or_else(|| take_value(a, "--deny", &mut rest))
        {
            inv.lints.push(LintFlag {
                level: "deny",
                name: v,
            });
        } else if let Some(v) =
            short_value(a, "-F", &mut rest).or_else(|| take_value(a, "--forbid", &mut rest))
        {
            inv.lints.push(LintFlag {
                level: "forbid",
                name: v,
            });
        } else if let Some(v) = take_value(a, "--force-warn", &mut rest) {
            inv.lints.push(LintFlag {
                level: "force-warn",
                name: v,
            });
        } else if a == "-" {
            match stdin_digest.clone() {
                Some(d) => match inv.source {
                    None => inv.source = Some(SourceInput::Stdin(d)),
                    Some(ref prev) => {
                        return Err(ParseError::MultipleSources(format!("{prev:?}"), arg));
                    }
                },
                None => return Err(ParseError::StdinWithoutDigest),
            }
        } else if !a.starts_with('-') && a.ends_with(".rs") {
            match inv.source {
                None => inv.source = Some(SourceInput::Path(arg)),
                Some(ref prev) => {
                    return Err(ParseError::MultipleSources(format!("{prev:?}"), arg));
                }
            }
        } else {
            // Sound-by-inclusion: unknown flags key conservatively.
            inv.passthrough.push(arg);
        }
    }
    Ok(inv)
}

impl NormalizedRustcInvocation {
    /// Canonical bytes for keying (F012). Wrapper diagnostics,
    /// `compiler_argv0`, and the excluded presentation flags do NOT
    /// participate; every semantic group does, in preserved order.
    ///
    /// Precondition (enforced by the F012 pipeline): path-bearing fields
    /// have been mapped to canonical execroot form (F004).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut enc = CanonicalEncoder::new();
        match &self.source {
            None => {
                enc.u64(0);
            }
            Some(SourceInput::Path(p)) => {
                enc.u64(1).str(p);
            }
            Some(SourceInput::Stdin(d)) => {
                enc.u64(2).str(d.domain).bytes(&d.bytes);
            }
        }
        enc.opt_str(self.crate_name.as_deref())
            .str_seq(&self.crate_types)
            .opt_str(self.edition.as_deref())
            .opt_str(self.target.as_deref())
            .str_seq(&self.emit)
            .pair_seq(&self.codegen)
            .pair_seq(&self.unstable)
            .str_seq(&self.cfgs)
            .str_seq(&self.features);
        enc.u64(self.lints.len() as u64);
        for l in &self.lints {
            enc.str(l.level).str(&l.name);
        }
        enc.opt_str(self.cap_lints.as_deref())
            .pair_seq(&self.externs)
            .str_seq(&self.lib_search)
            .str_seq(&self.native_libs)
            .opt_str(self.out_dir.as_deref())
            .str_seq(&self.passthrough);
        enc.finish()
    }
}

/// Small encoder conveniences local to this module.
trait EncoderExt {
    fn opt_str(&mut self, v: Option<&str>) -> &mut Self;
    fn str_seq(&mut self, v: &[String]) -> &mut Self;
    fn pair_seq(&mut self, v: &[(String, Option<String>)]) -> &mut Self;
}

impl EncoderExt for CanonicalEncoder {
    fn opt_str(&mut self, v: Option<&str>) -> &mut Self {
        match v {
            None => self.u64(0),
            Some(s) => self.u64(1).str(s),
        }
    }
    fn str_seq(&mut self, v: &[String]) -> &mut Self {
        self.u64(v.len() as u64);
        for s in v {
            self.str(s);
        }
        self
    }
    fn pair_seq(&mut self, v: &[(String, Option<String>)]) -> &mut Self {
        self.u64(v.len() as u64);
        for (n, val) in v {
            self.str(n).opt_str(val.as_deref());
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn digest() -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.stdin-content.v1",
            bytes: [7; 32],
        }
    }

    /// A realistic cargo-emitted stable-channel rustc argv.
    fn stable_fixture() -> Vec<String> {
        args(&[
            "/home/u/.rustup/toolchains/stable/bin/rustc",
            "--crate-name",
            "serde",
            "--edition=2021",
            "src/lib.rs",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "-C",
            "opt-level=3",
            "-C",
            "embed-bitcode=no",
            "--cfg",
            "feature=\"std\"",
            "--cfg",
            "feature=\"derive\"",
            "--cfg",
            "docsrs",
            "-D",
            "warnings",
            "--cap-lints",
            "allow",
            "-L",
            "dependency=/w/target/debug/deps",
            "--extern",
            "serde_derive=/w/target/debug/deps/libserde_derive.so",
            "--out-dir",
            "/w/target/debug/deps",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--color",
            "always",
            "--diagnostic-width=142",
        ])
    }

    #[test]
    fn stable_shape_parses_into_semantic_groups() {
        let inv = parse(&stable_fixture(), None).unwrap();
        assert_eq!(inv.crate_name.as_deref(), Some("serde"));
        assert_eq!(inv.edition.as_deref(), Some("2021"));
        assert_eq!(inv.crate_types, ["lib"]);
        assert_eq!(inv.emit, ["dep-info", "metadata", "link"]);
        assert_eq!(inv.source, Some(SourceInput::Path("src/lib.rs".into())));
        assert_eq!(inv.features, ["std", "derive"], "feature order preserved");
        assert_eq!(inv.cfgs, ["docsrs"], "non-feature cfg separated");
        assert_eq!(
            inv.codegen,
            [
                ("opt-level".to_owned(), Some("3".to_owned())),
                ("embed-bitcode".to_owned(), Some("no".to_owned())),
            ]
        );
        assert_eq!(
            inv.lints,
            [LintFlag {
                level: "deny",
                name: "warnings".into()
            }]
        );
        assert_eq!(inv.cap_lints.as_deref(), Some("allow"));
        assert_eq!(inv.externs.len(), 1);
        assert_eq!(inv.lib_search, ["dependency=/w/target/debug/deps"]);
        assert_eq!(inv.target.as_deref(), Some("x86_64-unknown-linux-gnu"));
        // Presentation flags dropped AND recorded.
        assert_eq!(
            inv.excluded_presentation,
            ["--color", "--diagnostic-width=142"]
        );
        assert!(inv.passthrough.is_empty(), "{:?}", inv.passthrough);
    }

    #[test]
    fn nested_wrapper_chain_decodes_to_the_real_compiler() {
        // sccache -> rch shim -> rustc, with a wrapper-only flag.
        let mut argv = args(&[
            "/usr/bin/sccache",
            "--wrapper-verbose",
            "/opt/rch/rch-shim",
            "/home/u/.rustup/toolchains/nightly/bin/rustc",
        ]);
        argv.extend(stable_fixture().into_iter().skip(1));
        let inv = parse(&argv, None).unwrap();
        assert_eq!(inv.wrapper_chain, ["sccache", "rch-shim"]);
        assert_eq!(inv.stripped_wrapper_flags, ["--wrapper-verbose"]);
        assert!(inv.compiler_argv0.ends_with("nightly/bin/rustc"));
        assert_eq!(inv.crate_name.as_deref(), Some("serde"));
        // The wrapper spelling never reaches canonical bytes: same
        // semantic argv with NO wrappers keys identically.
        let bare = parse(&stable_fixture(), None).unwrap();
        assert_eq!(inv.canonical_bytes(), bare.canonical_bytes());
    }

    #[test]
    fn stdin_requires_digest_and_keys_by_content() {
        let argv = args(&["rustc", "--crate-name", "probe", "-", "--emit=metadata"]);
        assert_eq!(parse(&argv, None), Err(ParseError::StdinWithoutDigest));
        let inv = parse(&argv, Some(digest())).unwrap();
        assert_eq!(inv.source, Some(SourceInput::Stdin(digest())));
        // Different stdin content (digest) -> different canonical bytes.
        let mut other = digest();
        other.bytes = [8; 32];
        let inv2 = parse(&argv, Some(other)).unwrap();
        assert_ne!(inv.canonical_bytes(), inv2.canonical_bytes());
    }

    #[test]
    fn nightly_exotics_and_unknown_flags_key_conservatively() {
        let argv = args(&[
            "rustc",
            "-Zunstable-options",
            "-Ctarget-cpu=native",
            "-l",
            "static=z",
            "--force-warn",
            "rust-2021-compatibility",
            "--json=artifacts",
            "--totally-new-flag=whatever",
            "lib.rs",
        ]);
        let inv = parse(&argv, None).unwrap();
        assert_eq!(inv.unstable, [("unstable-options".to_owned(), None)]);
        assert_eq!(
            inv.codegen,
            [("target-cpu".to_owned(), Some("native".to_owned()))]
        );
        assert_eq!(inv.native_libs, ["static=z"]);
        assert_eq!(inv.lints[0].level, "force-warn");
        // PLANTED soundness check: the unknown flags are NOT dropped —
        // they persist in passthrough and change the key.
        assert_eq!(
            inv.passthrough,
            ["--json=artifacts", "--totally-new-flag=whatever"]
        );
        let without: Vec<String> = argv
            .iter()
            .filter(|a| !a.starts_with("--totally-new-flag"))
            .cloned()
            .collect();
        let inv2 = parse(&without, None).unwrap();
        assert_ne!(
            inv.canonical_bytes(),
            inv2.canonical_bytes(),
            "an unknown flag MUST affect the key (sound-by-inclusion)"
        );
    }

    #[test]
    fn presentation_flags_never_affect_canonical_bytes() {
        let with = parse(&stable_fixture(), None).unwrap();
        let stripped: Vec<String> = {
            let mut v = stable_fixture();
            v.truncate(v.len() - 3); // drop --color always --diagnostic-width=142
            v
        };
        let without = parse(&stripped, None).unwrap();
        assert_eq!(with.canonical_bytes(), without.canonical_bytes());
        // …while a REAL semantic difference (a feature) does change them.
        let mut extra = stripped;
        extra.push("--cfg".into());
        extra.push("feature=\"alloc\"".into());
        let changed = parse(&extra, None).unwrap();
        assert_ne!(with.canonical_bytes(), changed.canonical_bytes());
    }

    #[test]
    fn separate_and_attached_value_forms_normalize_identically() {
        // beta/stable channels emit both spellings; they are one meaning.
        let a = parse(
            &args(&["rustc", "--edition", "2018", "-C", "opt-level=2", "m.rs"]),
            None,
        )
        .unwrap();
        let b = parse(
            &args(&["rustc", "--edition=2018", "-Copt-level=2", "m.rs"]),
            None,
        )
        .unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn degenerate_argvs_fail_typed() {
        assert_eq!(parse(&[], None), Err(ParseError::EmptyArgv));
        assert_eq!(
            parse(&args(&["--just-a-flag"]), None),
            Err(ParseError::NoCompilerInChain)
        );
        assert!(matches!(
            parse(&args(&["rustc", "a.rs", "b.rs"]), None),
            Err(ParseError::MultipleSources(_, _))
        ));
    }
}
