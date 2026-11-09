//! Exact Go executable selection and fresh-file execution.
//!
//! `go list` exposes the install Target built by the same DefaultExecName
//! method that `go build` uses for its implicit output. Only its basename is
//! authority here: dispatcher and worker installation directories may differ.
//! Package discovery uses readonly module modes and an external module cache,
//! runs before any source-directory staging, and is repeated by the selected
//! worker before compilation. Its package-index cache is disabled.

use super::{NativeOutputContract, compiler_arguments, literal_words};
use anyhow::{Context, Result, ensure};
use rch_common::patterns::GoBuildInvocation;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

const MAX_PROBE_BYTES: usize = 65_536;
const MAX_SOURCE_ANCESTORS: usize = 128;
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PACKAGE_FORMAT: &str = "{{.Name}}{{\"\\n\"}}{{.ImportPath}}{{\"\\n\"}}{{.Target}}";

/// Asking Go for CGO settings probes the C compiler and writes support flags
/// into GOCACHE, even with CGO_ENABLED=0. Disabling that cache makes `go env`
/// fail. Keep those control-only files in a private directory whose parent is
/// physically outside the protected source tree; actual compilation never
/// inherits these settings. Process-group ownership also covers compiler
/// probes and cancellation, rather than only the foreground shell.
struct LocalProbeRuntime {
    _directory: tempfile::TempDir,
    assignments: String,
}

impl LocalProbeRuntime {
    fn create(source_root: &Path) -> Result<Self> {
        let source = std::fs::canonicalize(source_root)
            .context("resolve protected source for Go control probes")?;
        ensure!(
            source.is_dir(),
            "protected Go source root is not a directory"
        );
        for parent in [
            std::env::temp_dir(),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
        ] {
            let Ok(parent) = std::fs::canonicalize(parent) else {
                continue;
            };
            if !parent.is_dir()
                || parent.starts_with(&source)
                || parent
                    .to_str()
                    .is_none_or(|text| text.chars().any(char::is_control))
            {
                continue;
            }
            // A parent of the source root is allowed: tempfile creates a new
            // uniquely owned sibling, never reuses an existing source path.
            let Ok(directory) = tempfile::Builder::new()
                .prefix("rch-go-probe.")
                .tempdir_in(parent)
            else {
                continue;
            };
            let temporary = directory.path().join("tmp");
            std::fs::create_dir(&temporary)
                .context("create private Go control temporary directory")?;
            let cache = directory.path().join("cache");
            let mut assignments = String::new();
            for (key, path) in [
                ("GOCACHE", &cache),
                ("GOTMPDIR", &temporary),
                ("TMPDIR", &temporary),
                ("TMP", &temporary),
                ("TEMP", &temporary),
            ] {
                let value = shell_escape::escape(
                    path.to_str()
                        .context("non-UTF-8 Go control runtime")?
                        .into(),
                );
                assignments.push_str(&format!("export {key}={value}; "));
            }
            return Ok(Self {
                _directory: directory,
                assignments,
            });
        }
        anyhow::bail!("no private Go control temporary directory outside protected source")
    }
}

// Query names explicitly: older Go versions return an empty string for newer
// settings, so a worker gaining a new default cannot silently skip comparison.
const GO_BUILD_ENVIRONMENT: &[&str] = &[
    "GOFLAGS",
    "GOOS",
    "GOARCH",
    "GOVERSION",
    "CGO_ENABLED",
    "GOEXPERIMENT",
    "GODEBUG",
    "GO386",
    "GOAMD64",
    "GOARM",
    "GOARM64",
    "GOMIPS",
    "GOMIPS64",
    "GOPPC64",
    "GORISCV64",
    "GOWASM",
    "GOFIPS140",
    "CC",
    "CXX",
    "FC",
    "AR",
    "PKG_CONFIG",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_FFLAGS",
    "CGO_LDFLAGS",
];

#[derive(Clone, Debug)]
struct PackageWitness {
    import_path: String,
    output: String,
}

impl PackageWitness {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("non-UTF-8 Go package discovery")?;
        let mut fields = text
            .strip_suffix('\n')
            .context("unterminated Go package discovery")?
            .split('\n');
        ensure!(
            fields.next() == Some("main"),
            "implicit Go output requires one main package"
        );
        let import_path = fields.next().context("Go package has no import path")?;
        let target = fields
            .next()
            .context("Go package has no executable target")?;
        ensure!(
            fields.next().is_none()
                && !import_path.is_empty()
                && !import_path.chars().any(char::is_control)
                && !target.chars().any(char::is_control)
                && Path::new(target).is_absolute(),
            "implicit Go output requires one complete package and an absolute install target"
        );
        let output = Path::new(target)
            .file_name()
            .and_then(|name| name.to_str())
            .context("Go install target has no executable filename")?;
        ensure!(
            NativeOutputContract::from_paths([output.to_owned()]).is_some(),
            "Go executable filename is not a supported project-relative file"
        );
        Ok(Self {
            import_path: import_path.to_owned(),
            output: output.to_owned(),
        })
    }

    fn worker_check(&self) -> String {
        let prefix = shell_escape::escape(format!("main\n{}\n", self.import_path).into());
        let output = shell_escape::escape(self.output.as_str().into());
        let newline = shell_escape::escape("\n".into());
        format!(
            "rch_go_package_newline={newline}; \
             case \"$rch_go_package\" in *\"$rch_go_package_newline\") \
               rch_go_package=${{rch_go_package%\"$rch_go_package_newline\"}};; *) \
               printf '%s\\n' 'RCH: worker Go package query is unterminated' >&2; exit 113;; esac; \
             rch_go_package_prefix={prefix}; \
             case \"$rch_go_package\" in \"$rch_go_package_prefix\"/*) ;; *) \
               printf '%s\\n' 'RCH: worker Go package selection differs from the dispatcher' >&2; exit 113;; esac; \
             rch_go_target=${{rch_go_package#\"$rch_go_package_prefix\"}}; \
             if ! (LC_ALL=C; export LC_ALL; case \"$rch_go_target\" in *[[:cntrl:]]*) exit 1;; esac); then \
               printf '%s\\n' 'RCH: worker Go package query returned extra or malformed records' >&2; exit 113; fi; \
             if [ \"${{rch_go_target##*/}}\" != {output} ]; then \
               printf '%s\\n' 'RCH: worker Go executable name differs from the dispatcher' >&2; exit 113; fi; "
        )
    }
}

/// The caller's effective compiler settings and exact promised file. Recovery
/// persists only the output contract; it never reruns discovery or compilation.
#[derive(Clone, Debug)]
pub(in crate::hook) struct GoBuildEnvironment {
    settings: String,
    output: NativeOutputContract,
    implicit: Option<PackageWitness>,
    source_ancestors: usize,
}

impl GoBuildEnvironment {
    pub(in crate::hook) fn output_contract(&self) -> NativeOutputContract {
        self.output.clone()
    }
}

pub(super) fn invocation(command: &str) -> Option<GoBuildInvocation> {
    let args = compiler_arguments(command, &["go"])?;
    let plain = shell_words::join(std::iter::once("go").chain(args.iter().map(String::as_str)));
    rch_common::patterns::go_build_invocation(&plain)
}

fn shell_command(command: &str, script: String, args: &[String]) -> Option<String> {
    // Linux also bounds each individual exec argument. Keep the generated
    // shell program bounded, including the literal package-query arguments.
    if script.len() > MAX_PROBE_BYTES {
        return None;
    }
    let mut words = literal_words(command)?;
    let original = compiler_arguments(command, &["go"])?;
    let go_index = words.len().checked_sub(original.len() + 1)?;
    let go = words.get(go_index)?.clone();
    words.truncate(go_index);
    words.extend([
        "sh".to_owned(),
        "-c".to_owned(),
        format!("rch_go=$1; shift; {script}"),
        "rch-go-output".to_owned(),
        go,
    ]);
    words.extend_from_slice(args);
    Some(super::super::super::join_exec_command(&words))
}

/// Command substitution must not allocate an unbounded package census. The
/// unique completion frame preserves the Go exit status through the bounded
/// reader; a truncated prefix cannot stand in for a completed successful query.
/// Assign the captured bytes instead of printing them into another command
/// substitution, which would discard significant trailing record terminators.
/// Both local ownership and the worker's execution supervisor include all
/// members of this pipeline in their existing cancellation/deadline scope.
fn capture_function() -> String {
    let marker = format!("RCH_GO_QUERY_END_{}", uuid::Uuid::new_v4());
    let suffix = shell_escape::escape(format!("\n{marker}:0").into());
    format!(
        "rch_go_capture() {{ \
           rch_go_frame=$({{ \"$@\"; rch_go_query_status=$?; \
             printf '\\n{marker}:%s\\n' \"$rch_go_query_status\"; }} | head -c {limit}) || return 113; \
           case \"$rch_go_frame\" in *{suffix}) \
             rch_go_capture_output=${{rch_go_frame%{suffix}}};; *) \
             printf '%s\\n' 'RCH: Go output query failed or exceeded its bound' >&2; return 113;; esac; \
         }}; ",
        limit = MAX_PROBE_BYTES + 1,
    )
}

fn environment_check(settings: &str) -> String {
    let query = shell_words::join(GO_BUILD_ENVIRONMENT);
    let expected = shell_escape::escape(settings.into());
    format!(
        "rch_go_capture \"$rch_go\" env -json {query} || exit 113; \
         rch_go_settings=$rch_go_capture_output; \
         if [ \"$rch_go_settings\" != {expected} ]; then \
           printf '%s\\n' 'RCH: worker Go compiler/code-generation settings differ from the dispatcher' >&2; exit 113; fi; "
    )
}

/// Resolve the full protected source root, not just a workspace invocation
/// directory. Cache roots are compiler configuration, not portable source:
/// keep their location unchanged and refuse overlapping placement before Go
/// can download, unpack, or create a lock/index inside selected source.
fn module_cache_check(source_ancestors: usize) -> String {
    let source = if source_ancestors == 0 {
        ".".to_owned()
    } else {
        vec![".."; source_ancestors].join("/")
    };
    let source = shell_escape::escape(source.into());
    let newline = shell_escape::escape("\n".into());
    format!(
        "rch_go_path_newline={newline}; \
         rch_go_read_path() {{ \
           case \"$rch_go_capture_output\" in *\"$rch_go_path_newline\") \
             rch_go_path=${{rch_go_capture_output%\"$rch_go_path_newline\"}};; *) \
             printf '%s\\n' 'RCH: unterminated Go module cache/source path' >&2; return 113;; esac; \
           if ! (LC_ALL=C; export LC_ALL; case \"$rch_go_path\" in *[[:cntrl:]]*) exit 1;; esac); then \
             printf '%s\\n' 'RCH: Go module cache/source path contains control characters' >&2; return 113; fi; \
           case \"$rch_go_path\" in /*) ;; *) \
             printf '%s\\n' 'RCH: Go module cache/source path is not absolute' >&2; return 113;; esac; \
           case \"$rch_go_path\" in /) ;; */|*//*|*/./*|*/../*|*/.|*/..) \
             printf '%s\\n' 'RCH: Go module cache/source path is not normalized' >&2; return 113;; esac; \
         }}; \
         rch_go_check_cache_overlap() {{ \
           case \"${{rch_go_cache%/}}/\" in \"${{rch_go_source%/}}/\"*) \
             printf '%s\\n' 'RCH: Go module cache overlaps protected source' >&2; return 113;; esac; \
           case \"${{rch_go_source%/}}/\" in \"${{rch_go_cache%/}}/\"*) \
             printf '%s\\n' 'RCH: Go module cache contains protected source' >&2; return 113;; esac; \
         }}; \
         rch_go_capture sh -c 'CDPATH= cd -P \"$1\" && pwd -P' rch-go-source {source} || exit 113; \
         rch_go_read_path || exit 113; rch_go_source=$rch_go_path; \
         GOTOOLCHAIN=local rch_go_capture \"$rch_go\" env GOMODCACHE || exit 113; \
         rch_go_read_path || exit 113; rch_go_cache=$rch_go_path; \
         rch_go_check_cache_overlap || exit 113; \
         rch_go_cache_prefix=$rch_go_cache; rch_go_cache_missing=; rch_go_cache_steps=0; \
         while [ ! -e \"$rch_go_cache_prefix\" ] && [ ! -L \"$rch_go_cache_prefix\" ]; do \
           rch_go_cache_steps=$((rch_go_cache_steps + 1)); \
           if [ \"$rch_go_cache_steps\" -gt {MAX_SOURCE_ANCESTORS} ]; then \
             printf '%s\\n' 'RCH: Go module cache exceeds its ancestor bound' >&2; exit 113; fi; \
           rch_go_cache_component=${{rch_go_cache_prefix##*/}}; \
           rch_go_cache_missing=$rch_go_cache_component${{rch_go_cache_missing:+/}}$rch_go_cache_missing; \
           rch_go_cache_prefix=${{rch_go_cache_prefix%/*}}; \
           if [ -z \"$rch_go_cache_prefix\" ]; then rch_go_cache_prefix=/; fi; \
         done; \
         if [ ! -d \"$rch_go_cache_prefix\" ]; then \
           printf '%s\\n' 'RCH: Go module cache has a dangling link or non-directory ancestor' >&2; exit 113; fi; \
         rch_go_capture sh -c 'CDPATH= cd -P \"$1\" && pwd -P' rch-go-cache \"$rch_go_cache_prefix\" || exit 113; \
         rch_go_read_path || exit 113; rch_go_cache=$rch_go_path; \
         if [ -n \"$rch_go_cache_missing\" ]; then \
           rch_go_cache=${{rch_go_cache%/}}/$rch_go_cache_missing; fi; \
         rch_go_check_cache_overlap || exit 113; "
    )
}

fn package_query_preflight(source_ancestors: usize) -> String {
    let off = shell_escape::escape("off\n".into());
    let empty = shell_escape::escape("\n".into());
    let caches = module_cache_check(source_ancestors);
    format!(
        "rch_go_capture \"$rch_go\" env GOWORK || exit 113; \
         case \"$rch_go_capture_output\" in {empty}|{off}) ;; *) \
           printf '%s\\n' 'RCH: implicit Go output discovery does not support workspace mode' >&2; exit 113;; esac; \
         {caches}"
    )
}

fn package_query(invocation: &GoBuildInvocation) -> String {
    let mut args = vec!["list".to_owned()];
    args.extend_from_slice(&invocation.build_flags);
    // These are query-only options. Preserve all package-selection flags,
    // including explicit readonly/vendor and the compiler's auto-vendor mode.
    // VCS stamping cannot affect the package's name or default filename.
    args.extend([
        "-find".to_owned(),
        "-buildvcs=false".to_owned(),
        "-f".to_owned(),
        PACKAGE_FORMAT.to_owned(),
    ]);
    args.extend_from_slice(&invocation.packages);
    let query = shell_words::join(args);
    format!(
        "GOCACHE=off GOWORK=off rch_go_capture \"$rch_go\" {query} || exit 113; \
         rch_go_package=$rch_go_capture_output; "
    )
}

#[cfg(unix)]
async fn probe(command: &str, root: &Path, deadline: tokio::time::Instant) -> Result<Vec<u8>> {
    use std::process::Stdio;
    use tokio::io::{AsyncRead, AsyncReadExt};

    async fn read(reader: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_PROBE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > MAX_PROBE_BYTES {
            return Err(std::io::Error::other(
                "Go output preflight exceeded its byte bound",
            ));
        }
        Ok(bytes)
    }

    let mut command_process = tokio::process::Command::new("sh");
    command_process
        .args(["-c", command])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = rch_common::ssh::OwnedProcessGroup::spawn(&mut command_process)
        .context("local Go output preflight could not run")?;
    let stdout = process
        .take_stdout()
        .context("missing Go preflight stdout")?;
    let stderr = process
        .take_stderr()
        .context("missing Go preflight stderr")?;
    let exchange = async {
        let (stdout, stderr) = tokio::try_join!(read(stdout), read(stderr))?;
        let status = process.wait().await?;
        ensure!(
            status.success(),
            "local Go output preflight refused remote execution: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
        Ok(stdout)
    };
    tokio::time::timeout_at(deadline, exchange)
        .await
        .context("local Go output preflight timed out")?
}

#[cfg(not(unix))]
async fn probe(_command: &str, _root: &Path, _deadline: tokio::time::Instant) -> Result<Vec<u8>> {
    anyhow::bail!("Go output preflight requires a Unix dispatcher")
}

fn readonly_package_discovery_supported(version: &str) -> bool {
    // Go 1.16 made ordinary module commands readonly by default. Requiring
    // 1.18 also supplies GOWORK and the query-only -buildvcs option. Unknown
    // development/major-version formats remain local instead of guessing.
    version
        .strip_prefix("go1.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|minor| minor.parse::<u32>().ok())
        .is_some_and(|minor| minor >= 18)
}

fn native_go_target() -> Option<(&'static str, &'static str)> {
    let goos = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        "dragonfly" => "dragonfly",
        _ => return None,
    };
    let goarch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "arm" => "arm",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        _ => return None,
    };
    Some((goos, goarch))
}

fn validate_destination(root: &Path, contract: &NativeOutputContract) -> Result<()> {
    contract.patterns()?;
    for relative in &contract.required_files {
        let mut path = root.to_owned();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            ensure!(
                matches!(component, Component::Normal(_)),
                "invalid Go output path"
            );
            path.push(component.as_os_str());
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error).context("inspect Go output destination"),
            };
            ensure!(
                !metadata.file_type().is_symlink()
                    && if components.peek().is_some() {
                        metadata.is_dir()
                    } else {
                        metadata.is_file()
                    },
                "Go output must be a regular file below real directories: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn source_ancestor_depth(invocation_root: &Path, source_root: &Path) -> Result<usize> {
    let invocation =
        std::fs::canonicalize(invocation_root).context("resolve Go invocation source directory")?;
    let source = std::fs::canonicalize(source_root).context("resolve protected Go source root")?;
    for path in [&invocation, &source] {
        let text = path
            .to_str()
            .context("non-UTF-8 protected Go source path")?;
        ensure!(
            !text.chars().any(char::is_control),
            "protected Go source path contains control characters"
        );
    }
    let relative = invocation
        .strip_prefix(&source)
        .context("Go invocation is outside its protected source root")?;
    let depth = relative.components().count();
    ensure!(
        depth <= MAX_SOURCE_ANCESTORS,
        "Go invocation exceeds its source ancestor bound"
    );
    Ok(depth)
}

/// Resolve the caller's exact promised file before upload or compilation.
/// A successful library/multiple-package build promises no implicit binary and
/// must not be changed into one by injecting our private execution -o option.
pub(in crate::hook) async fn validate_go_build_output(
    command: &str,
    project_root: &Path,
    source_root: &Path,
) -> Result<GoBuildEnvironment> {
    let invocation = invocation(command).context("Go build has no supported output contract")?;
    let runtime = LocalProbeRuntime::create(source_root)?;
    let source_ancestors = if invocation.output.is_none() {
        source_ancestor_depth(project_root, source_root)?
    } else {
        0
    };
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let query = shell_words::join(GO_BUILD_ENVIRONMENT);
    let initial_paths = if invocation.output.is_none() {
        // Toolchain startup may download into GOMODCACHE before executing
        // `go env`. Inspect its placement with GOTOOLCHAIN=local first; the
        // subsequent settings probe still selects the caller's real toolchain.
        format!(
            "{}{}",
            capture_function(),
            package_query_preflight(source_ancestors)
        )
    } else {
        String::new()
    };
    let environment_command = shell_command(
        command,
        format!(
            "{}{initial_paths}\"$rch_go\" env -json {query}",
            runtime.assignments
        ),
        &[],
    )
    .context("Go build has unsupported wrappers")?;
    let settings = String::from_utf8(probe(&environment_command, project_root, deadline).await?)
        .context("non-UTF-8 Go build environment")?;
    let values: BTreeMap<String, String> =
        serde_json::from_str(&settings).context("invalid Go build environment")?;
    ensure!(
        values.len() == GO_BUILD_ENVIRONMENT.len()
            && GO_BUILD_ENVIRONMENT
                .iter()
                .all(|name| values.contains_key(*name)),
        "incomplete Go build environment"
    );
    let (goos, goarch) = native_go_target().context("unsupported native Go target")?;
    ensure!(
        values["GOFLAGS"].is_empty() && values["GOOS"] == goos && values["GOARCH"] == goarch,
        "Go output delivery requires empty GOFLAGS and the dispatcher native GOOS/GOARCH"
    );
    let (output, implicit, source_ancestors) = if let Some(output) = &invocation.output {
        (
            NativeOutputContract::from_paths([output.path.clone()])
                .context("invalid explicit Go file output")?,
            None,
            0,
        )
    } else {
        ensure!(
            readonly_package_discovery_supported(&values["GOVERSION"]),
            "implicit Go output discovery requires a release Go toolchain version 1.18 or newer"
        );
        let script = format!(
            "{}{}{}{}{}printf '%s' \"$rch_go_package\"",
            runtime.assignments,
            capture_function(),
            package_query_preflight(source_ancestors),
            environment_check(&settings),
            package_query(&invocation),
        );
        let query_command = shell_command(command, script, &[])
            .context("Go package query exceeds its command bound")?;
        let witness = PackageWitness::parse(&probe(&query_command, project_root, deadline).await?)?;
        let output = NativeOutputContract::from_paths([witness.output.clone()])
            .context("invalid implicit Go file output")?;
        (output, Some(witness), source_ancestors)
    };
    validate_destination(project_root, &output)?;
    let environment = GoBuildEnvironment {
        settings,
        output,
        implicit,
        source_ancestors,
    };
    ensure!(
        go_build_execution_command(command, &environment, None).is_some(),
        "Go execution guard exceeds its command bound"
    );
    Ok(environment)
}

fn managed_runtime_assignments(runtime: Option<&BTreeMap<String, String>>) -> Option<String> {
    const KEYS: &[&str] = &[
        "GOCACHE",
        "GOMODCACHE",
        "GOPATH",
        "GOTMPDIR",
        "TMPDIR",
        "TMP",
        "TEMP",
    ];
    let Some(runtime) = runtime else {
        return Some(String::new());
    };
    if runtime.len() != KEYS.len() {
        return None;
    }
    let mut assignments = String::new();
    for &key in KEYS {
        let value = runtime.get(key)?;
        let path = Path::new(value);
        if value.len() > 16 * 1024
            || value.chars().any(char::is_control)
            || !path.is_absolute()
            || !path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            || !path
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
        {
            return None;
        }
        let escaped = shell_escape::escape(value.as_str().into());
        assignments.push_str(&format!("export {key}={escaped}; "));
    }
    Some(assignments)
}

/// Preserve wrappers and original build arguments. Compile outside the source
/// root, then atomically replace the requested destination with a fresh file.
/// Query and package loading precede any new source-directory staging, which
/// would otherwise change wildcard go:embed inputs.
pub(in crate::hook) fn go_build_execution_command(
    command: &str,
    environment: &GoBuildEnvironment,
    managed_runtime: Option<&BTreeMap<String, String>>,
) -> Option<String> {
    let invocation = invocation(command)?;
    match (&invocation.output, &environment.implicit) {
        (Some(selection), None)
            if NativeOutputContract::from_paths([selection.path.clone()])?
                == environment.output => {}
        (None, Some(_)) => {}
        _ => return None,
    }
    let output = environment.output.required_files.first()?;
    if environment.output.required_files.len() != 1 {
        return None;
    }
    let output_text = shell_escape::escape(format!("./{}", output.to_str()?).into());
    let mut path_checks = String::new();
    for parent in output
        .ancestors()
        .skip(1)
        .filter(|path| !path.as_os_str().is_empty())
    {
        let parent = shell_escape::escape(format!("./{}", parent.to_str()?).into());
        path_checks.push_str(&format!(
            "if [ -L {parent} ] || {{ [ -e {parent} ] && [ ! -d {parent} ]; }}; then \
             printf '%s\\n' 'RCH: Go output parents must be real directories' >&2; return 113; fi; "
        ));
    }
    path_checks.push_str(&format!(
        "if [ -L {output_text} ] || {{ [ -e {output_text} ] && [ ! -f {output_text} ]; }}; then \
         printf '%s\\n' 'RCH: Go output must name a regular file, not a directory or symlink' >&2; return 113; fi; "
    ));
    let mut preflight = capture_function();
    if environment.implicit.is_some() {
        // Cheap path admission precedes costly CGO environment probes. A
        // source-local module cache is refused without warming any cache.
        preflight.push_str(&package_query_preflight(environment.source_ancestors));
    }
    preflight.push_str(&environment_check(&environment.settings));
    let build_environment = if let Some(witness) = &environment.implicit {
        preflight.push_str(&package_query(&invocation));
        preflight.push_str(&witness.worker_check());
        // Freeze the no-workspace mode just admitted by both sides. A new
        // ancestor go.work between discovery and compilation cannot silently
        // change selection or cause a supposedly readonly query to write sums.
        "GOWORK=off "
    } else {
        ""
    };
    let parent = shell_escape::escape(format!("./{}", output.parent()?.to_str()?).into());
    // These values come from the pipeline's exact granted runtime placement.
    // Bind inside the wrapper-preserving shell: a leading user `env` command
    // must not restore cache/temp paths outside that grant after the pipeline
    // applies its outer environment. Compiler selection and settings remain
    // unchanged, and the actual build keeps its managed cache enabled.
    let runtime = managed_runtime_assignments(managed_runtime)?;
    let script = format!(
        "{runtime}rch_go_check_output() {{ {path_checks} return 0; }}; \
         rch_go_check_output || exit 113; \
         {preflight}\
         rch_go_root=$(pwd -P) || exit 113; \
         rch_go_build=$(mktemp -d \"${{TMPDIR:-/tmp}}/rch-go-build.XXXXXXXXXX\") || exit 113; \
         rch_go_stage=; \
         trap 'rm -f \"$rch_go_build/output\"; rmdir \"$rch_go_build\"; \
           if [ -n \"$rch_go_stage\" ]; then rm -f \"$rch_go_stage/output\"; rmdir \"$rch_go_stage\"; fi' EXIT; \
         trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
         rch_go_build_root=$(cd \"$rch_go_build\" && pwd -P) || exit 113; \
         case \"$rch_go_build_root/\" in \"${{rch_go_root%/}}/\"*) \
           printf '%s\\n' 'RCH: Go build temporary directory must be outside the source root' >&2; exit 113;; esac; \
         {build_environment}\"$rch_go\" build -o \"$rch_go_build/output\" \"$@\"; \
         rch_go_status=$?; \
         if [ \"$rch_go_status\" -ne 0 ]; then exit \"$rch_go_status\"; fi; \
         if [ -L \"$rch_go_build/output\" ] || [ ! -f \"$rch_go_build/output\" ]; then \
           printf '%s\\n' 'RCH: Go build succeeded without its required output file' >&2; exit 113; fi; \
         rch_go_parent={parent}; \
         rch_go_check_output || exit 113; \
         mkdir -p \"$rch_go_parent\" || exit 113; \
         rch_go_check_output || exit 113; \
         rch_go_stage=$(mktemp -d \"$rch_go_parent/.rch-go-output.XXXXXXXXXX\") || exit 113; \
         cp -p \"$rch_go_build/output\" \"$rch_go_stage/output\" || exit 113; \
         rch_go_check_output || exit 113; \
         mv -f \"$rch_go_stage/output\" {output_text} || exit 113"
    );
    let mut args = invocation.build_flags;
    args.extend(invocation.packages);
    shell_command(command, script, &args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_witness_requires_one_complete_main_record() {
        for target in ["/dispatcher/bin/server", "/worker/other/bin/server"] {
            let witness = PackageWitness::parse(
                format!("main\nexample.invalid/server/v2\n{target}\n").as_bytes(),
            )
            .unwrap();
            assert_eq!(witness.import_path, "example.invalid/server/v2");
            assert_eq!(witness.output, "server");
        }
        for reply in [
            "library\nexample.invalid/library\n/install/library\n",
            "main\nexample.invalid/server\n\n",
            "main\nexample.invalid/server\nrelative/server\n",
            "main\n\n/install/server\n",
            "main\nexample.invalid/server\n/install/../\n",
            "main\nexample.invalid/ser\tver\n/install/server\n",
            "main\nexample.invalid/server\n/install/ser\rver\n",
            "main\nexample.invalid/server\n/install/server",
            "main\nexample.invalid/server\n/install/server\n\n",
            "main\nexample.invalid/server\n/install/server\nmain\nexample.invalid/other\n/install/other\n",
        ] {
            assert!(
                PackageWitness::parse(reply.as_bytes()).is_err(),
                "{reply:?}"
            );
        }
        for version in ["go1.18", "go1.18.10", "go1.25.3"] {
            assert!(readonly_package_discovery_supported(version), "{version}");
        }
        for version in [
            "",
            "go1.15.15",
            "go1.17",
            "go1.18beta1",
            "devel go1.27",
            "go2.1",
        ] {
            assert!(!readonly_package_discovery_supported(version), "{version}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn worker_witness_rejects_additional_records_and_changed_selection() {
        let witness = PackageWitness {
            import_path: "example.invalid/server/v2".to_owned(),
            output: "server".to_owned(),
        };
        for (record, admitted) in [
            (
                "main\nexample.invalid/server/v2\n/other/install/server",
                true,
            ),
            (
                "main\nexample.invalid/server/v2\n/other/install/renamed",
                false,
            ),
            (
                "main\nexample.invalid/other/v2\n/other/install/server",
                false,
            ),
            (
                "library\nexample.invalid/server/v2\n/other/install/server",
                false,
            ),
            ("main\nexample.invalid/server/v2\nrelative/server", false),
            (
                "main\nexample.invalid/server/v2\n/other\tinstall/server",
                false,
            ),
            (
                "main\nexample.invalid/server/v2\n/other/install/server\n",
                false,
            ),
            (
                "main\nexample.invalid/server/v2\n/other/install/server\nmain\nexample.invalid/other\n/install/other",
                false,
            ),
        ] {
            let record = shell_escape::escape(format!("{record}\n").into());
            let output = std::process::Command::new("sh")
                .args([
                    "-c",
                    &format!("rch_go_package={record}; {}", witness.worker_check()),
                ])
                .output()
                .unwrap();
            assert_eq!(output.status.success(), admitted, "{record}: {output:?}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn bounded_query_capture_requires_complete_success() {
        for (program, admitted, expected) in [
            ("printf 'one\\ntwo\\n'", true, "one\ntwo\n"),
            ("printf 'plausible\\n'; exit 7", false, ""),
            ("printf '%65537s' x", false, ""),
        ] {
            let script = format!(
                "{}rch_go_capture sh -c {} && printf '%s' \"$rch_go_capture_output\"",
                capture_function(),
                shell_escape::escape(program.into())
            );
            let output = std::process::Command::new("sh")
                .args(["-c", &script])
                .output()
                .unwrap();
            assert_eq!(output.status.success(), admitted, "{program}: {output:?}");
            assert_eq!(output.stdout, expected.as_bytes(), "{program}");
        }
    }

    #[test]
    fn managed_runtime_accepts_only_complete_absolute_cache_and_temp_bindings() {
        let runtime = BTreeMap::from([
            ("GOCACHE".to_owned(), "/owned/runtime/cache".to_owned()),
            ("GOMODCACHE".to_owned(), "/owned/runtime/modules".to_owned()),
            ("GOPATH".to_owned(), "/owned/runtime/path".to_owned()),
            ("GOTMPDIR".to_owned(), "/owned/runtime/tmp".to_owned()),
            ("TMPDIR".to_owned(), "/owned/runtime/tmp".to_owned()),
            ("TMP".to_owned(), "/owned/runtime/tmp".to_owned()),
            ("TEMP".to_owned(), "/owned/runtime/tmp".to_owned()),
        ]);
        assert_eq!(managed_runtime_assignments(None), Some(String::new()));
        let assignments = managed_runtime_assignments(Some(&runtime)).unwrap();
        assert_eq!(assignments.matches("export ").count(), runtime.len());
        assert!(!assignments.contains("export PATH="));
        assert!(!assignments.contains("export CC="));
        let mut missing = runtime.clone();
        missing.remove("TMP");
        assert!(managed_runtime_assignments(Some(&missing)).is_none());
        let mut unrelated = runtime.clone();
        unrelated.insert("PATH".to_owned(), "/different/toolchain".to_owned());
        assert!(managed_runtime_assignments(Some(&unrelated)).is_none());
        for invalid in [
            "relative/cache",
            "/",
            "/owned/../unowned",
            "/owned/cache\nnext",
        ] {
            let mut changed = runtime.clone();
            changed.insert("GOMODCACHE".to_owned(), invalid.to_owned());
            assert!(
                managed_runtime_assignments(Some(&changed)).is_none(),
                "{invalid:?}"
            );
        }
    }
}
