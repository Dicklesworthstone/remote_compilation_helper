//! Native Linux live Cargo acceptance suite runner (`rabs-live-test`).
//!
//! Builds matching workspace binaries through Cargo's JSON artifact stream,
//! fingerprints each exact executable via a stable file descriptor, writes
//! create-only `0600` `binaries.json` and `run.json` preparation records, and
//! executes the live acceptance suite while preserving inherited jobserver
//! descriptors and original stdout/stderr streams.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

const HELP: &str = "Build matching binaries, then run a real Cargo RABS acceptance suite.

Usage: rabs-live-test [--suite worktrees|canonical]
                      [--profile PROFILE] [--target-dir DIR]
                      [--output-dir NEW_DIR] [--cargo CARGO]
                      [--workspace DIR] [-- LIBTEST_ARGS...]

Options:
  --suite SUITE       Acceptance suite: worktrees (default) or canonical
  --profile PROFILE   Cargo build profile (default: daemon-release)
  --target-dir DIR    Explicit Cargo target directory
  --output-dir DIR    New directory for binaries.json, run.json, and Cargo logs
  --cargo CARGO       Cargo executable (default: $CARGO or cargo)
  --workspace DIR     Workspace root containing Cargo.toml (default: auto-detected)
  --version           Print version
  -h, --help          Print help

Requires Linux and the repository Rust toolchain. Build and test failures
propagate without retries, warmup builds, or Cargo configuration edits.
";

#[cfg(target_os = "linux")]
mod runner {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
    use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value, json};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fmt;
    use std::fs::{self, File};
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    const SCHEMA_WORKTREES: &str = "rabs.test-binaries";
    const SCHEMA_CANONICAL: &str = "rabs.canonical-test-binaries";
    const MANIFEST_ENV: &str = "RABS_TEST_BINARIES";
    const MAX_FRAME: usize = 4 * 1024 * 1024;
    const MAX_LOG: usize = 64 * 1024 * 1024;
    const WORKTREE_NAMES: [&str; 2] = ["rabs-wrap", "rabsd"];
    const CANONICAL_BUILD_NAMES: [&str; 3] = ["rabs-wrap", "rabs-wkr", "rabs-cargo-root"];
    const CANONICAL_TEST_NAMES: [&str; 2] = ["rabsd", "canonical_check_local"];

    fn binary_source(name: &str) -> Option<&'static str> {
        match name {
            "rabs-wrap" => Some("rabs-wrap/src/main.rs"),
            "rabsd" => Some("rabsd/src/main.rs"),
            "rabs-wkr" => Some("rabs-wkr/src/main.rs"),
            "rabs-cargo-root" => Some("rabs-wkr/src/bin/rabs-cargo-root.rs"),
            "canonical_check_local" => Some("rabsd/tests/canonical_check_local.rs"),
            _ => None,
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Suite {
        Worktrees,
        Canonical,
    }

    impl Suite {
        fn as_str(self) -> &'static str {
            match self {
                Self::Worktrees => "worktrees",
                Self::Canonical => "canonical",
            }
        }
    }

    #[derive(Debug)]
    pub struct CliArgs {
        pub profile: String,
        pub suite: Suite,
        pub target_dir: Option<PathBuf>,
        pub output_dir: Option<PathBuf>,
        pub cargo: String,
        pub workspace: Option<PathBuf>,
        pub test_args: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct Fingerprint {
        pub path: String,
        pub sha256: String,
        pub size: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Stamp {
        dev: i128,
        ino: i128,
        size: i128,
        mode: u32,
        mtime: (i128, i128),
        ctime: (i128, i128),
    }

    impl Stamp {
        fn of(stat: &Stat) -> Self {
            Self {
                dev: i128::from(stat.st_dev),
                ino: i128::from(stat.st_ino),
                size: i128::from(stat.st_size),
                mode: stat.st_mode,
                mtime: (i128::from(stat.st_mtime), i128::from(stat.st_mtime_nsec)),
                ctime: (i128::from(stat.st_ctime), i128::from(stat.st_ctime_nsec)),
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        out
    }

    /// Parse one Cargo JSON frame while strictly rejecting duplicate keys at
    /// every object depth.
    pub fn decode_frame(data: &[u8]) -> Result<Map<String, Value>, String> {
        struct StrictValue(Value);

        impl<'de> Deserialize<'de> for StrictValue {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct StrictVisitor;

                impl<'de> Visitor<'de> for StrictVisitor {
                    type Value = StrictValue;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("valid JSON with unique object keys")
                    }

                    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                        Ok(StrictValue(Value::Bool(v)))
                    }

                    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                        Ok(StrictValue(Value::Number(v.into())))
                    }

                    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                        Ok(StrictValue(Value::Number(v.into())))
                    }

                    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                        serde_json::Number::from_f64(v)
                            .map(|n| StrictValue(Value::Number(n)))
                            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                        Ok(StrictValue(Value::String(v.to_owned())))
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                        Ok(StrictValue(Value::String(v)))
                    }

                    fn visit_unit<E>(self) -> Result<Self::Value, E> {
                        Ok(StrictValue(Value::Null))
                    }

                    fn visit_seq<A: SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<Self::Value, A::Error> {
                        let mut out = Vec::new();
                        while let Some(StrictValue(elem)) = seq.next_element::<StrictValue>()? {
                            out.push(elem);
                        }
                        Ok(StrictValue(Value::Array(out)))
                    }

                    fn visit_map<A: MapAccess<'de>>(
                        self,
                        mut map: A,
                    ) -> Result<Self::Value, A::Error> {
                        let mut out = Map::new();
                        while let Some((key, StrictValue(val))) =
                            map.next_entry::<String, StrictValue>()?
                        {
                            if out.insert(key.clone(), val).is_some() {
                                return Err(de::Error::custom(format!(
                                    "duplicate Cargo JSON field: {key}"
                                )));
                            }
                        }
                        Ok(StrictValue(Value::Object(out)))
                    }
                }

                deserializer.deserialize_any(StrictVisitor)
            }
        }

        let text = std::str::from_utf8(data).map_err(|_| "invalid Cargo JSON output".to_owned())?;
        let mut de = serde_json::Deserializer::from_str(text);
        let StrictValue(value) = StrictValue::deserialize(&mut de).map_err(|err| {
            let msg = err.to_string();
            if msg.contains("duplicate Cargo JSON field:") {
                msg
            } else {
                "invalid Cargo JSON output".to_owned()
            }
        })?;
        de.end()
            .map_err(|_| "invalid Cargo JSON output".to_owned())?;
        match value {
            Value::Object(obj) => Ok(obj),
            _ => Err("Cargo JSON frame is not an object".to_owned()),
        }
    }

    /// Hash one exact regular executable through a single non-blocking,
    /// no-follow, close-on-exec file descriptor, verifying identity before and
    /// after streaming.
    pub fn fingerprint(path: &Path) -> Result<Fingerprint, String> {
        if !path.is_absolute() {
            return Err("Cargo artifact path is not absolute".to_owned());
        }
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|err| format!("failed to open Cargo artifact {}: {err}", path.display()))?;
        let mut file = File::from(fd);
        let before = rustix::fs::fstat(&file)
            .map_err(|err| format!("fstat failed for {}: {err}", path.display()))?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_mode & 0o111 == 0
        {
            return Err(format!(
                "Cargo artifact is not a regular executable: {}",
                path.display()
            ));
        }
        let lstat_before = rustix::fs::statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|err| format!("lstat failed for {}: {err}", path.display()))?;
        let stamp_before = Stamp::of(&before);
        if Stamp::of(&lstat_before) != stamp_before {
            return Err("Cargo artifact changed while opening".to_owned());
        }

        let size = u64::try_from(before.st_size)
            .map_err(|_| "Cargo artifact has negative size".to_owned())?;
        let mut remaining = size;
        let mut hasher = Sha256::new();
        let mut buf = [0_u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = file
                .read(&mut buf[..want])
                .map_err(|err| format!("failed reading {}: {err}", path.display()))?;
            if n == 0 {
                return Err("Cargo artifact was truncated while hashing".to_owned());
            }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }
        let trailing = file
            .read(&mut buf[..1])
            .map_err(|err| format!("failed reading {}: {err}", path.display()))?;
        let fstat_after =
            rustix::fs::fstat(&file).map_err(|err| format!("fstat after hash failed: {err}"))?;
        let lstat_after = rustix::fs::statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|err| format!("lstat after hash failed: {err}"))?;
        if trailing != 0
            || Stamp::of(&fstat_after) != stamp_before
            || Stamp::of(&lstat_after) != stamp_before
        {
            return Err("Cargo artifact changed while hashing".to_owned());
        }

        Ok(Fingerprint {
            path: path.display().to_string(),
            sha256: hex(&hasher.finalize()),
            size,
        })
    }

    struct CargoArtifacts<'a> {
        workspace: &'a Path,
        names: &'a [&'static str],
        executables: BTreeMap<String, PathBuf>,
        finished: Option<bool>,
    }

    impl<'a> CargoArtifacts<'a> {
        fn new(workspace: &'a Path, names: &'a [&'static str]) -> Self {
            Self {
                workspace,
                names,
                executables: BTreeMap::new(),
                finished: None,
            }
        }

        fn accept(&mut self, value: &Map<String, Value>) -> Result<(), String> {
            let Some(reason) = value.get("reason").and_then(Value::as_str) else {
                return Ok(());
            };
            if reason == "build-finished" {
                let success = value.get("success").and_then(Value::as_bool);
                if self.finished.is_some() || success.is_none() {
                    return Err("ambiguous Cargo build-finished record".to_owned());
                }
                self.finished = success;
                return Ok(());
            }
            if reason != "compiler-artifact" {
                return Ok(());
            }
            let Some(target) = value.get("target").and_then(Value::as_object) else {
                return Ok(());
            };
            let Some(name) = target.get("name").and_then(Value::as_str) else {
                return Ok(());
            };
            if !self.names.contains(&name) {
                return Ok(());
            }
            let Some(profile) = value.get("profile").and_then(Value::as_object) else {
                return Ok(());
            };
            let harness = name == "canonical_check_local";
            let expected_kind = if harness { "test" } else { "bin" };
            let kind_matches = target
                .get("kind")
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.len() == 1 && arr[0].as_str() == Some(expected_kind));
            if !kind_matches || profile.get("test").and_then(Value::as_bool) != Some(harness) {
                return Ok(());
            }

            let expected_src = self.workspace.join(
                binary_source(name)
                    .ok_or_else(|| format!("unexpected binary target name: {name}"))?,
            );
            let source_matches = target
                .get("src_path")
                .and_then(Value::as_str)
                .is_some_and(|src| Path::new(src) == expected_src);
            if !source_matches {
                return Err(format!("Cargo reported {name} from another source tree"));
            }

            let Some(executable) = value.get("executable").and_then(Value::as_str) else {
                return Err(format!("Cargo did not name an absolute {name} executable"));
            };
            let exec_path = PathBuf::from(executable);
            if !exec_path.is_absolute() {
                return Err(format!("Cargo did not name an absolute {name} executable"));
            }
            if let Some(previous) = self.executables.get(name)
                && previous != &exec_path
            {
                return Err(format!("Cargo reported multiple {name} executables"));
            }
            self.executables.insert(name.to_owned(), exec_path);
            Ok(())
        }

        fn finish(&self) -> Result<BTreeMap<String, Fingerprint>, String> {
            if self.finished != Some(true) {
                return Err("Cargo did not confirm a successful build".to_owned());
            }
            let mut missing = Vec::new();
            for &name in self.names {
                if !self.executables.contains_key(name) {
                    missing.push(name);
                }
            }
            if !missing.is_empty() {
                missing.sort_unstable();
                return Err(format!(
                    "Cargo did not report required binary artifacts: {}",
                    missing.join(", ")
                ));
            }
            let mut out = BTreeMap::new();
            for &name in self.names {
                let fp = fingerprint(&self.executables[name])?;
                out.insert(name.to_owned(), fp);
            }
            Ok(out)
        }
    }

    pub fn write_new_json(path: &Path, value: &Value) -> Result<(), String> {
        let fd = rustix::fs::open(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        let mut file = File::from(fd);
        serde_json::to_writer_pretty(&mut file, value)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        file.write_all(b"\n")
            .map_err(|err| format!("failed to finish {}: {err}", path.display()))?;
        Ok(())
    }

    fn create_private_log(path: &Path) -> Result<File, String> {
        let fd = rustix::fs::open(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        Ok(File::from(fd))
    }

    fn status_to_code(status: ExitStatus) -> i32 {
        if let Some(code) = status.code() {
            code
        } else if let Some(sig) = status.signal() {
            -sig
        } else {
            1
        }
    }

    /// Read one newline-delimited frame bounded by `max_len + 1` bytes.
    fn read_bounded_line<R: BufRead>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        max_len: usize,
    ) -> io::Result<usize> {
        buf.clear();
        let mut total = 0usize;
        loop {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok(total);
            }
            let newline = available.iter().position(|&b| b == b'\n');
            let take = match newline {
                Some(idx) => idx + 1,
                None => available.len(),
            };
            let room = (max_len + 1).saturating_sub(total);
            let copy = take.min(room);
            buf.extend_from_slice(&available[..copy]);
            reader.consume(copy);
            total += copy;
            if newline.is_some() && copy == take {
                return Ok(total);
            }
            if total > max_len {
                return Ok(total);
            }
        }
    }

    struct ReapChild(Option<std::process::Child>);

    impl Drop for ReapChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn collect_build(
        cargo: &Path,
        args: &[String],
        workspace: &Path,
        env: &BTreeMap<OsString, OsString>,
        log: &mut File,
        names: &[&'static str],
    ) -> Result<(i32, Option<BTreeMap<String, Fingerprint>>), String> {
        let mut collector = CargoArtifacts::new(workspace, names);
        // Rust's std::process::Command preserves inherited non-CLOEXEC jobserver
        // descriptors while O_CLOEXEC on our log/manifest descriptors keeps our
        // private files from leaking into Cargo.
        let mut cmd = Command::new(cargo);
        cmd.args(args)
            .current_dir(workspace)
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut spawned = ReapChild(Some(
            cmd.spawn()
                .map_err(|err| format!("failed to spawn Cargo: {err}"))?,
        ));
        let stdout = spawned
            .0
            .as_mut()
            .and_then(|c| c.stdout.take())
            .ok_or_else(|| "Cargo stdout pipe unavailable".to_owned())?;
        let mut reader = BufReader::new(stdout);
        let mut frame = Vec::new();
        let mut failure: Option<String> = None;
        let mut total = 0usize;
        loop {
            let n = read_bounded_line(&mut reader, &mut frame, MAX_FRAME)
                .map_err(|err| format!("failed reading Cargo stdout: {err}"))?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n);
            if n > MAX_FRAME || total > MAX_LOG {
                failure = Some("Cargo output exceeded the preparation log/frame bound".to_owned());
            }
            if failure.is_none() {
                log.write_all(&frame)
                    .map_err(|err| format!("failed writing build log: {err}"))?;
                match decode_frame(&frame).and_then(|obj| collector.accept(&obj)) {
                    Ok(()) => {}
                    Err(err) => failure = Some(err),
                }
            }
            if failure.is_some() {
                // Drain remaining stdout so Cargo never deadlocks on a full pipe.
                let mut sink = [0_u8; 64 * 1024];
                while reader.read(&mut sink).unwrap_or(0) > 0 {}
                break;
            }
        }
        drop(reader);
        let mut child = spawned.0.take().expect("spawned child still owned");
        let status = child
            .wait()
            .map_err(|err| format!("failed waiting on Cargo: {err}"))?;
        let code = status_to_code(status);
        if code != 0 {
            return Ok((code, None));
        }
        if let Some(err) = failure {
            return Err(err);
        }
        Ok((0, Some(collector.finish()?)))
    }

    fn resolve_cargo(requested: &str) -> Result<PathBuf, String> {
        let candidate = Path::new(requested);
        if candidate.components().count() > 1 || candidate.is_absolute() {
            let abs = std::path::absolute(candidate)
                .map_err(|err| format!("invalid Cargo path {requested}: {err}"))?;
            let meta = fs::metadata(&abs)
                .map_err(|_| format!("Cargo executable was not found: {requested}"))?;
            if meta.is_file()
                && rustix::fs::accessat(
                    rustix::fs::CWD,
                    &abs,
                    rustix::fs::Access::EXEC_OK,
                    AtFlags::EACCESS,
                )
                .is_ok()
            {
                // Preserve the final symlink spelling so rustup dispatches properly.
                return Ok(abs);
            }
            return Err(format!("Cargo executable was not found: {requested}"));
        }
        let path_env = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path_env) {
            let full = dir.join(requested);
            let Ok(abs) = std::path::absolute(&full) else {
                continue;
            };
            if fs::metadata(&abs).is_ok_and(|m| m.is_file())
                && rustix::fs::accessat(
                    rustix::fs::CWD,
                    &abs,
                    rustix::fs::Access::EXEC_OK,
                    AtFlags::EACCESS,
                )
                .is_ok()
            {
                return Ok(abs);
            }
        }
        Err(format!("Cargo executable was not found: {requested}"))
    }

    fn detect_workspace() -> Result<PathBuf, String> {
        let mut cursor = std::env::current_dir()
            .map_err(|err| format!("failed to determine current directory: {err}"))?;
        loop {
            if cursor.join("Cargo.toml").is_file()
                && cursor.join("rabs-wrap/src/main.rs").is_file()
                && cursor.join("rabsd/src/main.rs").is_file()
            {
                return Ok(cursor);
            }
            if !cursor.pop() {
                break;
            }
        }
        Err("could not locate RABS workspace root (pass --workspace DIR)".to_owned())
    }

    pub fn parse_args(arguments: &[OsString]) -> Result<CliArgs, String> {
        let mut profile = "daemon-release".to_owned();
        let mut suite = Suite::Worktrees;
        let mut target_dir = None;
        let mut output_dir = None;
        let mut cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let mut workspace = None;
        let mut test_args = Vec::new();

        let mut iter = arguments.iter();
        while let Some(arg) = iter.next() {
            let text = arg
                .to_str()
                .ok_or_else(|| "non-UTF-8 command-line argument".to_owned())?;
            if text == "--" {
                for rest in iter {
                    test_args.push(
                        rest.to_str()
                            .ok_or_else(|| "non-UTF-8 test argument".to_owned())?
                            .to_owned(),
                    );
                }
                break;
            }
            let next_val = |opt: &str, iter: &mut std::slice::Iter<'_, OsString>| {
                iter.next()
                    .and_then(|v| v.to_str())
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{opt} requires a value"))
            };
            match text {
                "--profile" => profile = next_val("--profile", &mut iter)?,
                "--suite" => {
                    suite = match next_val("--suite", &mut iter)?.as_str() {
                        "worktrees" => Suite::Worktrees,
                        "canonical" => Suite::Canonical,
                        other => {
                            return Err(format!(
                                "invalid --suite {other:?} (expected worktrees or canonical)"
                            ));
                        }
                    };
                }
                "--target-dir" => {
                    target_dir = Some(PathBuf::from(next_val("--target-dir", &mut iter)?))
                }
                "--output-dir" => {
                    output_dir = Some(PathBuf::from(next_val("--output-dir", &mut iter)?))
                }
                "--cargo" => cargo = next_val("--cargo", &mut iter)?,
                "--workspace" => {
                    workspace = Some(PathBuf::from(next_val("--workspace", &mut iter)?))
                }
                _ if text.strip_prefix("--profile=").is_some() => {
                    profile = text.strip_prefix("--profile=").unwrap().to_owned();
                }
                _ if text.strip_prefix("--suite=").is_some() => {
                    suite = match text.strip_prefix("--suite=").unwrap() {
                        "worktrees" => Suite::Worktrees,
                        "canonical" => Suite::Canonical,
                        other => {
                            return Err(format!(
                                "invalid --suite {other:?} (expected worktrees or canonical)"
                            ));
                        }
                    };
                }
                _ if text.strip_prefix("--target-dir=").is_some() => {
                    let val = text.strip_prefix("--target-dir=").unwrap();
                    if val.is_empty() {
                        return Err("--target-dir requires a value".to_owned());
                    }
                    target_dir = Some(PathBuf::from(val));
                }
                _ if text.strip_prefix("--output-dir=").is_some() => {
                    let val = text.strip_prefix("--output-dir=").unwrap();
                    if val.is_empty() {
                        return Err("--output-dir requires a value".to_owned());
                    }
                    output_dir = Some(PathBuf::from(val));
                }
                _ if text.strip_prefix("--cargo=").is_some() => {
                    let val = text.strip_prefix("--cargo=").unwrap();
                    if val.is_empty() {
                        return Err("--cargo requires a value".to_owned());
                    }
                    cargo = val.to_owned();
                }
                _ if text.strip_prefix("--workspace=").is_some() => {
                    let val = text.strip_prefix("--workspace=").unwrap();
                    if val.is_empty() {
                        return Err("--workspace requires a value".to_owned());
                    }
                    workspace = Some(PathBuf::from(val));
                }
                _ if text.starts_with('-') => {
                    return Err(format!(
                        "unknown option {text:?} (pass libtest flags after --)"
                    ));
                }
                _ => {
                    test_args.push(text.to_owned());
                    for rest in iter {
                        test_args.push(
                            rest.to_str()
                                .ok_or_else(|| "non-UTF-8 test argument".to_owned())?
                                .to_owned(),
                        );
                    }
                    break;
                }
            }
        }

        if profile.is_empty()
            || !profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("profile must be a Cargo profile name".to_owned());
        }

        Ok(CliArgs {
            profile,
            suite,
            target_dir,
            output_dir,
            cargo,
            workspace,
            test_args,
        })
    }

    pub fn run(args: &CliArgs) -> Result<i32, String> {
        let workspace_raw = match &args.workspace {
            Some(path) => path.clone(),
            None => detect_workspace()?,
        };
        let workspace = fs::canonicalize(&workspace_raw).map_err(|err| {
            format!(
                "workspace root {} is not accessible: {err}",
                workspace_raw.display()
            )
        })?;
        let cargo = resolve_cargo(&args.cargo)?;
        let cargo_str = cargo.display().to_string();

        let target = {
            let raw = args
                .target_dir
                .clone()
                .or_else(|| std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from))
                .unwrap_or_else(|| workspace.join("target"));
            std::path::absolute(&raw)
                .map_err(|err| format!("invalid target dir {}: {err}", raw.display()))?
        };
        let output = match &args.output_dir {
            Some(dir) => std::path::absolute(dir)
                .map_err(|err| format!("invalid output dir {}: {err}", dir.display()))?,
            None => {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                target
                    .join("rabs-live-validation")
                    .join(format!("{}-{nanos}", std::process::id()))
            }
        };
        if let Some(parent) = output.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        // Create leaf directory strictly without overwriting an existing report dir.
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&output)
            .map_err(|err| {
                format!(
                    "failed to create output directory {}: {err}",
                    output.display()
                )
            })?;

        let common = vec![
            "--locked".to_owned(),
            "--manifest-path".to_owned(),
            workspace.join("Cargo.toml").display().to_string(),
            "--target-dir".to_owned(),
            target.display().to_string(),
            "--profile".to_owned(),
            args.profile.clone(),
        ];
        let canonical = args.suite == Suite::Canonical;
        let packages = if canonical {
            vec![
                "-p".to_owned(),
                "rabs-wrap".to_owned(),
                "-p".to_owned(),
                "rabs-wkr".to_owned(),
            ]
        } else {
            vec![
                "-p".to_owned(),
                "rabs-wrap".to_owned(),
                "-p".to_owned(),
                "rabsd".to_owned(),
            ]
        };
        let mut build = vec![cargo_str.clone(), "build".to_owned()];
        build.extend(common.iter().cloned());
        build.extend(packages);
        build.push("--bins".to_owned());
        build.push("--message-format=json-render-diagnostics".to_owned());

        let test_target = if canonical {
            vec![
                "-p".to_owned(),
                "rabsd".to_owned(),
                "--test".to_owned(),
                "canonical_check_local".to_owned(),
            ]
        } else {
            vec![
                "-p".to_owned(),
                "rabs-wrap".to_owned(),
                "--test".to_owned(),
                "live_cargo_worktrees".to_owned(),
            ]
        };
        let mut test_options = vec!["--nocapture".to_owned()];
        if canonical {
            test_options.push("--include-ignored".to_owned());
            if !args
                .test_args
                .iter()
                .any(|v| v == "--test-threads" || v.starts_with("--test-threads="))
            {
                test_options.push("--test-threads=1".to_owned());
            }
        }
        let mut test = vec![cargo_str.clone(), "test".to_owned()];
        test.extend(common.iter().cloned());
        test.extend(test_target.iter().cloned());
        test.push("--".to_owned());
        test.extend(test_options);
        test.extend(args.test_args.iter().cloned());

        let test_preparation = if canonical {
            let mut prep = vec![cargo_str, "test".to_owned()];
            prep.extend(common);
            prep.extend(test_target);
            prep.push("--no-run".to_owned());
            prep.push("--message-format=json-render-diagnostics".to_owned());
            Some(prep)
        } else {
            None
        };

        let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
        for key in [
            MANIFEST_ENV,
            "RABS_CANONICAL_TEST_WRAPPER",
            "RABS_TEST_WORKER_BIN",
        ] {
            env.remove(&OsString::from(key));
        }

        let mut report = json!({
            "schema": "rabs.live-test-run",
            "version": 1,
            "workspace_root": workspace.display().to_string(),
            "profile": args.profile,
            "suite": args.suite.as_str(),
            "build_source": env.get(&OsString::from("RCH_BUILD_SOURCE"))
                .and_then(|v| v.to_str())
                .map(str::to_owned),
            "build_command": build,
            "test_command": test,
            "test_preparation_command": test_preparation,
            "test_preparation_exit": Value::Null,
            "build_exit": Value::Null,
            "test_exit": Value::Null,
        });

        let start = Instant::now();
        let outcome: Result<i32, String> = (|| {
            eprintln!(
                "RABS binary preparation ({}) -> {}",
                args.profile,
                output.display()
            );
            let mut build_log = create_private_log(&output.join("cargo-build.jsonl"))?;
            let build_names: &[&'static str] = if canonical {
                &CANONICAL_BUILD_NAMES
            } else {
                &WORKTREE_NAMES
            };
            let (status, maybe_binaries) = collect_build(
                &cargo,
                &build[1..],
                &workspace,
                &env,
                &mut build_log,
                build_names,
            )?;
            drop(build_log);
            report["build_exit"] = json!(status);
            report["preparation_seconds"] = json!(start.elapsed().as_secs_f64());
            if status != 0 {
                return Ok(status);
            }
            let mut binaries = maybe_binaries
                .ok_or_else(|| "Cargo did not report required binaries".to_owned())?;
            if canonical {
                let wkr_parent = Path::new(&binaries["rabs-wkr"].path).parent();
                let root_parent = Path::new(&binaries["rabs-cargo-root"].path).parent();
                if wkr_parent != root_parent {
                    return Err("worker and Cargo supervisor artifacts are not siblings".to_owned());
                }
                let prep_cmd = test_preparation
                    .as_ref()
                    .expect("canonical suite prepares integration binary");
                let mut test_log = create_private_log(&output.join("cargo-test-build.jsonl"))?;
                let (prep_status, maybe_test_bins) = collect_build(
                    &cargo,
                    &prep_cmd[1..],
                    &workspace,
                    &env,
                    &mut test_log,
                    &CANONICAL_TEST_NAMES,
                )?;
                drop(test_log);
                report["test_preparation_exit"] = json!(prep_status);
                if prep_status != 0 {
                    return Ok(prep_status);
                }
                for (name, artifact) in &binaries {
                    if &fingerprint(Path::new(&artifact.path))? != artifact {
                        return Err(format!("test preparation changed the prepared {name}"));
                    }
                }
                let test_bins = maybe_test_bins
                    .ok_or_else(|| "Cargo did not report canonical test binaries".to_owned())?;
                binaries.extend(test_bins);
            }
            report["preparation_seconds"] = json!(start.elapsed().as_secs_f64());

            let manifest_path = output.join("binaries.json");
            let mut record = Map::new();
            record.insert(
                "schema".to_owned(),
                json!(if canonical {
                    SCHEMA_CANONICAL
                } else {
                    SCHEMA_WORKTREES
                }),
            );
            record.insert("version".to_owned(), json!(1));
            record.insert(
                "workspace_root".to_owned(),
                json!(workspace.display().to_string()),
            );
            record.insert("profile".to_owned(), json!(args.profile));
            for (name, fp) in &binaries {
                record.insert(
                    name.clone(),
                    serde_json::to_value(fp).map_err(|err| err.to_string())?,
                );
            }
            write_new_json(&manifest_path, &Value::Object(record))?;

            if canonical {
                env.insert(
                    OsString::from("RABS_CANONICAL_TEST_WRAPPER"),
                    OsString::from(&binaries["rabs-wrap"].path),
                );
                env.insert(
                    OsString::from("RABS_TEST_WORKER_BIN"),
                    OsString::from(&binaries["rabs-wkr"].path),
                );
            } else {
                env.insert(
                    OsString::from(MANIFEST_ENV),
                    manifest_path.as_os_str().to_owned(),
                );
            }

            eprintln!(
                "RABS live Cargo tests ({}) -> prepared binaries",
                args.suite.as_str()
            );
            let started_test = Instant::now();
            let mut test_cmd = Command::new(&cargo);
            test_cmd
                .args(&test[1..])
                .current_dir(&workspace)
                .env_clear()
                .envs(&env)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            let test_status = test_cmd
                .status()
                .map_err(|err| format!("failed to run Cargo test: {err}"))?;
            let test_code = status_to_code(test_status);
            report["test_seconds"] = json!(started_test.elapsed().as_secs_f64());
            report["test_exit"] = json!(test_code);

            if canonical {
                for (name, artifact) in &binaries {
                    if &fingerprint(Path::new(&artifact.path))? != artifact {
                        return Err(format!("test execution changed the prepared {name}"));
                    }
                }
            }
            Ok(test_code)
        })();

        if let Err(ref err) = outcome {
            report["preparation_error"] = json!(err);
        }
        report["elapsed_seconds"] = json!(start.elapsed().as_secs_f64());
        if let Err(write_err) = write_new_json(&output.join("run.json"), &report) {
            return match outcome {
                Err(orig) => Err(format!(
                    "{orig} (also failed writing run.json: {write_err})"
                )),
                Ok(_) => Err(write_err),
            };
        }
        outcome
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};

        #[test]
        fn decode_frame_rejects_duplicate_keys_and_non_objects() {
            assert!(decode_frame(br#"{"reason":"build-finished","success":true}"#).is_ok());
            assert!(
                decode_frame(br#"{"reason":"a","reason":"b"}"#)
                    .unwrap_err()
                    .contains("duplicate Cargo JSON field")
            );
            assert!(
                decode_frame(br#"{"nested":{"k":1,"k":2}}"#)
                    .unwrap_err()
                    .contains("duplicate Cargo JSON field")
            );
            assert!(decode_frame(b"[1, 2, 3]").is_err());
            assert!(decode_frame(b"{broken").is_err());
        }

        #[test]
        fn fingerprint_hashes_multibuffer_executable_and_rejects_nonexec_and_symlink() {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("binary");
            let data: Vec<u8> = (0..=255u8).cycle().take(256 * 1001).collect();
            fs::write(&bin, &data).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();

            let fp = fingerprint(&bin).unwrap();
            assert_eq!(fp.path, bin.display().to_string());
            assert_eq!(fp.size, data.len() as u64);
            assert_eq!(fp.sha256, hex(&Sha256::digest(&data)));

            // Non-executable fails.
            let nonexec = dir.path().join("nonexec");
            fs::write(&nonexec, b"data").unwrap();
            fs::set_permissions(&nonexec, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(fingerprint(&nonexec).is_err());

            // Symlink fails without following.
            let link = dir.path().join("link");
            symlink(&bin, &link).unwrap();
            assert!(fingerprint(&link).is_err());
        }

        #[test]
        fn write_new_json_is_create_only_and_private() {
            let dir = tempfile::tempdir().unwrap();
            let record = dir.path().join("record.json");
            write_new_json(&record, &json!({"original": true})).unwrap();
            assert!(write_new_json(&record, &json!({"original": false})).is_err());
            let parsed: Value =
                serde_json::from_str(&fs::read_to_string(&record).unwrap()).unwrap();
            assert_eq!(parsed, json!({"original": true}));
            let mode = fs::metadata(&record).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}

fn dispatch(arguments: &[OsString]) -> ExitCode {
    if let Some(info) =
        rabs_protocol::release_authorization::build_info_for_args("rabs-live-test", arguments)
    {
        if writeln!(io::stdout().lock(), "{info}").is_err() {
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }
    if arguments == [OsString::from("--version")] {
        println!("rabs-live-test {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if arguments == [OsString::from("--help")] || arguments == [OsString::from("-h")] {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    #[cfg(target_os = "linux")]
    {
        let args = match runner::parse_args(arguments) {
            Ok(args) => args,
            Err(error) => {
                eprintln!("RABS preparation failed: {error}");
                return ExitCode::from(2);
            }
        };
        match runner::run(&args) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(code) if code > 0 => ExitCode::from(u8::try_from(code).unwrap_or(1)),
            Ok(neg_signal) => {
                let sig = neg_signal.unsigned_abs();
                if let Ok(raw) = i32::try_from(sig)
                    && let Some(signal) = rustix::process::Signal::from_named_raw(raw)
                {
                    let _ = rustix::process::kill_process(rustix::process::getpid(), signal);
                }
                ExitCode::from(u8::try_from(128 + sig).unwrap_or(1))
            }
            Err(error) => {
                eprintln!("RABS preparation failed: {error}");
                ExitCode::from(2)
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("RABS preparation failed: the live Cargo acceptance suite requires Linux");
        ExitCode::from(2)
    }
}

fn main() -> ExitCode {
    dispatch(&std::env::args_os().skip(1).collect::<Vec<_>>())
}
