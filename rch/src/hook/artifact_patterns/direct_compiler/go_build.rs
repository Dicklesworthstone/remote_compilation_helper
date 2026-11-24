//! Exact Go executable/test-binary selection and fresh-file execution.
//!
//! `go list` exposes the install Target built by the same DefaultExecName
//! method that `go build` uses for its implicit output. Only its basename is
//! authority here: dispatcher and worker installation directories may differ.
//! Compile-only tests also support non-main packages: the compiler's selected
//! import path, package name, and effective module mode determine their default
//! filename, with actual test inputs required before promising a binary.
//! Package discovery uses readonly module modes and an external module cache,
//! runs before any source-directory staging, and is repeated by the selected
//! worker before compilation. Its package-index cache is disabled.

use super::{NativeOutputContract, compiler_arguments, literal_words};
use crate::hook::go_workspace::{self, GoSourcePlan};
use anyhow::{Context, Result, ensure};
use rch_common::path_topology::PathTopologyPolicy;
use rch_common::patterns::GoBuildOutput;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const MAX_PROBE_BYTES: usize = 65_536;
const MAX_SOURCE_ANCESTORS: usize = 128;
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PACKAGE_FORMAT: &str = "{{.Name}}{{\"\\n\"}}{{.ImportPath}}{{\"\\n\"}}{{.Target}}";
const TEST_PACKAGE_FORMAT: &str =
    "{{.ImportPath}}{{\"\\n\"}}{{len .TestGoFiles}}{{\"\\n\"}}{{len .XTestGoFiles}}";
const IMPLICIT_TEST_PACKAGE_FORMAT: &str = "{{.ImportPath}}{{\"\\n\"}}{{.Name}}{{\"\\n\"}}{{len .TestGoFiles}}{{\"\\n\"}}{{len .XTestGoFiles}}";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GoCompileMode {
    Build,
    Test,
    Coverage,
}

/// Read from the completed supervisor stderr log. A failed compiler may
/// produce no report; a failing test may produce one. Neither a pre-existing
/// file nor the bounded streaming preview establishes this attempt's result.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::hook) struct GoCoverageCapture {
    token: String,
    outcome: Option<GoCoverageOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum GoCoverageOutcome {
    Present { exit: i32 },
    Absent { exit: i32 },
    Rejected { exit: i32, reason: String },
}

impl GoCoverageCapture {
    pub(in crate::hook) fn validate(&self, exit: Option<i32>) -> Result<()> {
        ensure!(
            self.token.len() == 32
                && self
                    .token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid Go coverage attempt token"
        );
        if let Some(outcome) = &self.outcome {
            let observed_exit = match outcome {
                GoCoverageOutcome::Present { exit }
                | GoCoverageOutcome::Absent { exit }
                | GoCoverageOutcome::Rejected { exit, .. } => *exit,
            };
            ensure!(
                exit == Some(observed_exit)
                    && (0..=255).contains(&observed_exit)
                    && (!matches!(outcome, GoCoverageOutcome::Absent { .. }) || observed_exit != 0),
                "Go coverage outcome contradicts command completion"
            );
            if let GoCoverageOutcome::Rejected { reason, .. } = outcome {
                ensure!(
                    !reason.is_empty() && reason.len() <= 4096,
                    "invalid Go coverage rejection"
                );
            }
        }
        Ok(())
    }

    pub(in crate::hook) fn present(&self) -> Option<bool> {
        match &self.outcome {
            Some(GoCoverageOutcome::Present { .. }) => Some(true),
            Some(GoCoverageOutcome::Absent { .. }) => Some(false),
            _ => None,
        }
    }

    pub(in crate::hook) fn rejection(&self) -> Option<&str> {
        match &self.outcome {
            Some(GoCoverageOutcome::Rejected { reason, .. }) => Some(reason),
            _ => None,
        }
    }

    pub(in crate::hook) fn reject(&mut self, exit: i32, reason: &str) -> Result<()> {
        ensure!(
            self.outcome.is_none(),
            "Go coverage already has a completed outcome"
        );
        self.outcome = Some(GoCoverageOutcome::Rejected {
            exit,
            reason: reason.chars().take(1024).collect(),
        });
        self.validate(Some(exit))
    }

    pub(in crate::hook) fn suppress_line(&self, line: &str) -> bool {
        line.starts_with(&format!("RCH_GO_COVERAGE_V1 {} ", self.token))
    }

    pub(in crate::hook) fn accept(&mut self, stderr: &[u8], exit: i32) -> Result<()> {
        self.validate(Some(exit))?;
        ensure!(
            self.rejection().is_none(),
            "Go coverage was already rejected"
        );
        let prefix = format!("RCH_GO_COVERAGE_V1 {} ", self.token);
        let mut receipts = stderr
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| line.starts_with(prefix.as_bytes()));
        let receipt = receipts
            .next()
            .context("Go coverage outcome is unavailable")?;
        ensure!(receipts.next().is_none(), "ambiguous Go coverage outcomes");
        let present = if receipt == format!("{prefix}{exit} present\n").as_bytes() {
            true
        } else {
            ensure!(
                receipt == format!("{prefix}{exit} absent\n").as_bytes() && exit != 0,
                "invalid Go coverage outcome"
            );
            false
        };
        let outcome = if present {
            GoCoverageOutcome::Present { exit }
        } else {
            GoCoverageOutcome::Absent { exit }
        };
        ensure!(
            self.outcome
                .as_ref()
                .is_none_or(|previous| previous == &outcome),
            "Go coverage outcome changed after collection"
        );
        self.outcome = Some(outcome);
        Ok(())
    }
}

pub(super) struct GoCompileInvocation {
    mode: GoCompileMode,
    pub(super) output: Option<GoBuildOutput>,
    build_flags: Vec<String>,
    packages: Vec<String>,
}

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

/// A bounded command grammar shared with exact Go output admission. Streaming
/// tests add only test controls that do not introduce another input/output
/// path; their original argv is preserved for execution.
fn source_packages(command: &str) -> Option<Vec<String>> {
    if let Some(invocation) = invocation(command) {
        return Some(invocation.packages);
    }
    let args = compiler_arguments(command, &["go"])?;
    let subcommand = args.first()?.as_str();
    if !matches!(subcommand, "test" | "vet") {
        return None;
    }
    let mut query = if subcommand == "test" {
        vec!["go".to_owned(), "test".to_owned(), "-c".to_owned()]
    } else {
        vec!["go".to_owned(), "build".to_owned()]
    };
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        let (flag, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(flag, value)| {
                (flag, Some(value))
            });
        if subcommand == "test"
            && matches!(
                flag,
                "-run"
                    | "-skip"
                    | "-count"
                    | "-timeout"
                    | "-parallel"
                    | "-bench"
                    | "-benchtime"
                    | "-shuffle"
                    | "-cpu"
                    | "-list"
                    | "-vet"
            )
        {
            if inline.is_none() {
                index += 1;
                args.get(index)?;
            }
        } else if subcommand == "test"
            && matches!(
                flag,
                "-benchmem" | "-json" | "-failfast" | "-short" | "-fullpath"
            )
        {
            if inline.is_some_and(|value| !matches!(value, "true" | "false")) {
                return None;
            }
        } else {
            query.push(argument.clone());
            if inline.is_none()
                && matches!(
                    flag,
                    "-buildmode"
                        | "-compiler"
                        | "-p"
                        | "-tags"
                        | "-covermode"
                        | "-coverpkg"
                        | "-ldflags"
                        | "-mod"
                )
            {
                index += 1;
                query.push(args.get(index)?.clone());
            }
        }
        index += 1;
    }
    let query = shell_words::join(query);
    if subcommand == "test" {
        let parsed = rch_common::patterns::go_test_invocation(&query)?;
        parsed.output.is_none().then_some(parsed.packages)
    } else {
        let parsed = rch_common::patterns::go_build_invocation(&query)?;
        parsed.output.is_none().then_some(parsed.packages)
    }
}

#[allow(clippy::too_many_arguments)] // One probe's full context; a struct would only rename it.
async fn metadata_json(
    command: &str,
    invocation_root: &Path,
    runtime: &LocalProbeRuntime,
    topology: &PathTopologyPolicy,
    path: &Path,
    workspace: bool,
    index: usize,
    deadline: tokio::time::Instant,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // `edit -json` reads this immutable private copy. A source edit cannot
    // associate one graph's JSON with another graph's transferred manifest.
    let bytes = go_workspace::read_control_file(path, topology)?;
    let copied = runtime._directory.path().join(format!(
        "manifest-{index}.{}",
        if workspace { "work" } else { "mod" }
    ));
    std::fs::write(&copied, &bytes).context("capture Go discovery manifest")?;
    let copied = shell_escape::escape(copied.to_str().context("non-UTF-8 Go probe path")?.into());
    let subcommand = if workspace { "work" } else { "mod" };
    let query = shell_command(
        command,
        format!(
            "{}GOWORK=off GOTOOLCHAIN=local \"$rch_go\" {subcommand} edit -json {copied}",
            runtime.assignments
        ),
        &[],
    )
    .context("Go source discovery has unsupported wrappers")?;
    Ok((bytes, probe(&query, invocation_root, deadline).await?))
}

/// Ask the selected Go executable which module/workspace it really uses, then
/// close the declared local module graph before choosing a transfer root.
pub(in crate::hook) async fn discover_go_source(
    command: &str,
    invocation_root: &Path,
    topology: &PathTopologyPolicy,
) -> Result<Option<GoSourcePlan>> {
    let packages = source_packages(command)
        .context("Go source closure requires supported literal build/test/vet arguments")?;
    // The eventual module/workspace root may be an ancestor of the cwd. Keep
    // discovery scratch outside the entire admitted topology until that
    // boundary is known, not merely outside the invoking package directory.
    let runtime = LocalProbeRuntime::create(topology.canonical_root())?;
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let query = shell_command(
        command,
        format!(
            "{}GOTOOLCHAIN=local \"$rch_go\" env -json GOMOD GOWORK GOFLAGS",
            runtime.assignments
        ),
        &[],
    )
    .context("Go source discovery has unsupported wrappers")?;
    let settings: BTreeMap<String, String> =
        serde_json::from_slice(&probe(&query, invocation_root, deadline).await?)
            .context("invalid selected Go source environment")?;
    ensure!(
        settings.len() == 3
            && ["GOMOD", "GOWORK", "GOFLAGS"]
                .iter()
                .all(|name| settings.contains_key(*name))
            && settings["GOFLAGS"].is_empty(),
        "Go source closure requires empty GOFLAGS and a complete module environment"
    );
    let selected = |name: &str, sentinels: &[&str]| -> Result<Option<PathBuf>> {
        let value = &settings[name];
        if sentinels.contains(&value.as_str()) {
            return Ok(None);
        }
        let path = PathBuf::from(value);
        ensure!(
            path.is_absolute() && !value.chars().any(char::is_control),
            "Go selected an invalid {name} path"
        );
        Ok(Some(path))
    };
    let module = selected("GOMOD", &["", "/dev/null"])?;
    let workspace = selected("GOWORK", &["", "off"])?;
    if module.is_none() && workspace.is_none() {
        return Ok(None);
    }
    let mut captured = BTreeMap::new();
    let workspace_json = if let Some(path) = &workspace {
        let (bytes, json) = metadata_json(
            command,
            invocation_root,
            &runtime,
            topology,
            path,
            true,
            0,
            deadline,
        )
        .await?;
        captured.insert(path.clone(), bytes);
        Some(json)
    } else {
        None
    };
    let modules = match (&workspace, &workspace_json) {
        (Some(path), Some(json)) => go_workspace::workspace_modules(path, json, topology)?,
        _ => vec![
            module
                .as_ref()
                .context("Go module selection disappeared")?
                .parent()
                .context("Go module has no source directory")?
                .to_owned(),
        ],
    };
    let mut module_json = BTreeMap::new();
    for (index, root) in modules.into_iter().enumerate() {
        let path = root.join("go.mod");
        let (bytes, json) = metadata_json(
            command,
            invocation_root,
            &runtime,
            topology,
            &path,
            false,
            index + 1,
            deadline,
        )
        .await?;
        captured.insert(path, bytes);
        module_json.insert(root, json);
    }
    let plan = go_workspace::plan(
        invocation_root,
        module.as_deref(),
        workspace.as_deref(),
        workspace_json.as_deref(),
        &module_json,
        topology,
    )?;
    for (path, bytes) in captured {
        ensure!(
            plan.required_files
                .get(&path)
                .is_some_and(|content| content.as_bytes() == bytes),
            "Go control input changed while discovering its source closure: {}",
            path.display()
        );
    }
    for package in packages {
        if package.starts_with('.') || package.ends_with(".go") || Path::new(&package).is_absolute()
        {
            ensure!(
                !Path::new(&package).is_absolute(),
                "absolute Go package inputs are unsupported"
            );
            let mut path = invocation_root.to_owned();
            for part in Path::new(&package).components() {
                match part {
                    Component::CurDir => {}
                    Component::ParentDir => {
                        ensure!(path.pop(), "Go package escapes its source root");
                    }
                    Component::Normal(name) if name == "..." => break,
                    Component::Normal(name) => path.push(name),
                    _ => anyhow::bail!("invalid Go package path"),
                }
                ensure!(
                    path.starts_with(&plan.source_root),
                    "Go package is outside its source closure"
                );
                if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                    ensure!(
                        !metadata.file_type().is_symlink(),
                        "Go package input contains a symlink"
                    );
                }
            }
        }
    }
    Ok(Some(plan))
}

/// Use the upload's actual selected file paths, not another interpretation of
/// .rchignore. Retained excluded control files cannot satisfy this closure.
pub(in crate::hook) fn verify_go_source_selection(
    plan: &GoSourcePlan,
    transfer_root: &Path,
    selected: &[PathBuf],
    topology: &PathTopologyPolicy,
) -> Result<()> {
    let selected: BTreeSet<_> = selected.iter().collect();
    for (path, expected) in &plan.required_files {
        let relative = path
            .strip_prefix(transfer_root)
            .context("Go source input is outside its covering transfer")?;
        ensure!(
            selected.contains(&relative.to_path_buf()),
            "required Go source input {} is excluded from the actual source transfer",
            path.display()
        );
        ensure!(
            go_workspace::read_control_file(path, topology)? == expected.as_bytes(),
            "Go source input changed after closure discovery: {}",
            path.display()
        );
    }
    if let Some(vendor) = &plan.vendor_directory {
        ensure!(
            std::fs::symlink_metadata(vendor)?.is_dir(),
            "Go vendor directory changed after closure discovery: {}",
            vendor.display()
        );
    }
    for path in &plan.absent_files {
        ensure!(
            matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "absent Go source input appeared after closure discovery: {}",
            path.display()
        );
    }
    Ok(())
}

fn relative_source_path<'a>(root: &Path, path: &'a Path) -> Result<&'a str> {
    let relative = path
        .strip_prefix(root)
        .context("Go control input escaped source root")?;
    ensure!(
        !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "invalid relative Go control input"
    );
    let text = relative.to_str().context("non-UTF-8 Go control input")?;
    ensure!(
        !text.chars().any(char::is_control),
        "Go control input contains control characters"
    );
    Ok(text)
}

#[derive(Clone, Debug)]
struct GoSourceGuard {
    source_ancestors: usize,
    manifest: String,
    file_count: usize,
    byte_count: usize,
    absent: Vec<String>,
    workspace: Option<String>,
    workspace_sum: bool,
    vendor_directory: Option<String>,
    workspace_edits: String,
    selected_module: Option<String>,
}

impl GoSourceGuard {
    fn new(plan: &GoSourcePlan, invocation_root: &Path) -> Result<Self> {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let mut manifest = String::new();
        let mut byte_count = 0;
        for (path, bytes) in &plan.required_files {
            let relative = relative_source_path(&plan.source_root, path)?;
            let mode = usize::from(std::fs::metadata(path)?.permissions().mode() & 0o111 != 0);
            let mut hash = String::with_capacity(64);
            for byte in Sha256::digest(bytes.as_bytes()) {
                write!(hash, "{byte:02x}")?;
            }
            manifest.push_str(&format!("{hash}\t{}\t{mode}\t{relative}\n", bytes.len()));
            byte_count += bytes.len();
        }
        let mut workspace_edits = String::new();
        for argument in &plan.workspace_edit_args {
            let edit = if argument.starts_with("-dropuse=") {
                shell_escape::escape(argument.as_str().into()).into_owned()
            } else {
                let (prefix, path) = if let Some(path) = argument.strip_prefix("-use=") {
                    ("-use=".to_owned(), path)
                } else {
                    let (identity, path) = argument
                        .strip_prefix("-replace=")
                        .and_then(|value| value.split_once('='))
                        .context("invalid Go workspace relocation argument")?;
                    (format!("-replace={identity}="), path)
                };
                let relative = if Path::new(path) == plan.source_root {
                    "."
                } else {
                    relative_source_path(&plan.source_root, Path::new(path))?
                };
                format!(
                    "{}\"$rch_go_closure_root\"/{}",
                    shell_escape::escape(prefix.into()),
                    shell_escape::escape(relative.into())
                )
            };
            workspace_edits.push(' ');
            workspace_edits.push_str(&edit);
        }
        let workspace = plan
            .workspace
            .as_ref()
            .map(|path| relative_source_path(&plan.source_root, path).map(str::to_owned))
            .transpose()?;
        let workspace_sum = plan.workspace.as_ref().is_some_and(|path| {
            let mut sum = path.as_os_str().to_os_string();
            sum.push(".sum");
            plan.required_files.contains_key(&PathBuf::from(sum))
        });
        Ok(Self {
            source_ancestors: source_ancestor_depth(invocation_root, &plan.source_root)?,
            manifest,
            file_count: plan.required_files.len(),
            byte_count,
            absent: plan
                .absent_files
                .iter()
                .map(|path| relative_source_path(&plan.source_root, path).map(str::to_owned))
                .collect::<Result<_>>()?,
            workspace,
            workspace_sum,
            vendor_directory: plan
                .vendor_directory
                .as_ref()
                .map(|path| relative_source_path(&plan.source_root, path).map(str::to_owned))
                .transpose()?,
            workspace_edits,
            selected_module: plan
                .selected_module
                .as_ref()
                .map(|path| relative_source_path(&plan.source_root, path).map(str::to_owned))
                .transpose()?,
        })
    }

    fn worker_setup(&self) -> String {
        let source = ancestor_path(self.source_ancestors);
        let mut script = format!(
            "CDPATH= cd -P . || exit 113; \
             rch_go_closure_root=$(CDPATH= cd -P {source} && pwd -P) || exit 113; \
             {}\n\
             if ! rch_wkr_locate || \
                ! rch_go_verifier=$(\"$RCH_WKR\" verify-source-content probe </dev/null 2>/dev/null) || \
                [ \"$rch_go_verifier\" != RCH_SOURCE_CONTENT_VERIFIER_V1 ]; then \
               printf '%s\\n' 'RCH: Go source verification requires an up-to-date rch-wkr' >&2; exit 113; fi; \
             printf '%s' {} | \"$RCH_WKR\" verify-source-content verify \
               \"$rch_go_closure_root\" {} {} >/dev/null || exit 113; ",
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
            shell_escape::escape(self.manifest.as_str().into()),
            self.file_count,
            self.byte_count,
        );
        for path in &self.absent {
            let path = shell_escape::escape(path.as_str().into());
            script.push_str(&format!(
                "if [ -e \"$rch_go_closure_root\"/{path} ] || [ -L \"$rch_go_closure_root\"/{path} ]; then \
                 printf '%s\\n' 'RCH: worker has a stale Go control input absent from the dispatcher' >&2; exit 113; fi; "
            ));
        }
        let vendor = self
            .vendor_directory
            .as_deref()
            .map(|path| shell_escape::escape(path.into()));
        if let Some(path) = &vendor {
            script.push_str(&format!(
                "if [ ! -d \"$rch_go_closure_root\"/{path} ] || [ -L \"$rch_go_closure_root\"/{path} ]; then \
                 printf '%s\\n' 'RCH: worker Go vendor directory is missing or replaced' >&2; exit 113; fi; "
            ));
        }
        if let Some(workspace) = &self.workspace {
            let workspace = shell_escape::escape(workspace.as_str().into());
            script.push_str(&format!(
                "cp \"$rch_go_closure_root\"/{workspace} \"$rch_go_build/selection.work\" || exit 113; "
            ));
            if self.workspace_sum {
                script.push_str(&format!(
                    "cp \"$rch_go_closure_root\"/{workspace}.sum \"$rch_go_build/selection.work.sum\" || exit 113; "
                ));
            }
            if let Some(path) = &vendor {
                script.push_str(&format!(
                    "ln -s \"$rch_go_closure_root\"/{path} \"$rch_go_build/vendor\" || exit 113; "
                ));
            }
            script.push_str(&format!(
                "GOWORK=off GOTOOLCHAIN=local \"$rch_go\" work edit{} \"$rch_go_build/selection.work\" || exit 113; \
                 export GOWORK=\"$rch_go_build/selection.work\"; ", self.workspace_edits
            ));
        } else {
            script.push_str("export GOWORK=off; ");
        }
        let empty_flags = shell_escape::escape("\n".into());
        script.push_str(&format!(
            "rch_go_capture \"$rch_go\" env GOFLAGS || exit 113; \
             if [ \"$rch_go_capture_output\" != {empty_flags} ]; then \
               printf '%s\\n' 'RCH: worker Go source closure requires empty GOFLAGS' >&2; exit 113; fi; \
             rch_go_capture \"$rch_go\" env GOMOD || exit 113; "
        ));
        let selected = self.selected_module.as_ref().map_or_else(
            || shell_escape::escape("/dev/null\n".into()).into_owned(),
            |module| {
                format!(
                    "\"$rch_go_closure_root\"/{}",
                    shell_escape::escape(format!("{module}\n").into())
                )
            },
        );
        script.push_str(&format!(
            "if [ \"$rch_go_capture_output\" != {selected} ]; then \
               printf '%s\\n' 'RCH: worker selected a different Go module' >&2; exit 113; fi; "
        ));
        script
    }
}

fn ancestor_path(depth: usize) -> String {
    if depth == 0 {
        ".".to_owned()
    } else {
        vec![".."; depth].join("/")
    }
}

async fn local_workspace_environment(
    command: &str,
    invocation_root: &Path,
    plan: &GoSourcePlan,
    runtime: &LocalProbeRuntime,
    deadline: tokio::time::Instant,
) -> Result<String> {
    let Some(workspace) = &plan.workspace else {
        return Ok("export GOWORK=off; ".into());
    };
    let directory = runtime._directory.path();
    let copy = directory.join("selection.work");
    std::fs::write(
        &copy,
        plan.required_files
            .get(workspace)
            .context("Go workspace lost its captured bytes")?,
    )?;
    let mut sum = workspace.as_os_str().to_os_string();
    sum.push(".sum");
    if let Some(bytes) = plan.required_files.get(&PathBuf::from(sum)) {
        std::fs::write(directory.join("selection.work.sum"), bytes)?;
    }
    if let Some(vendor) = &plan.vendor_directory {
        std::os::unix::fs::symlink(vendor, directory.join("vendor"))?;
    }
    let copy = shell_escape::escape(
        copy.to_str()
            .context("non-UTF-8 private Go workspace")?
            .into(),
    );
    let edits = shell_words::join(&plan.workspace_edit_args);
    let query = shell_command(
        command,
        format!(
            "{}GOWORK=off GOTOOLCHAIN=local \"$rch_go\" work edit {edits} {copy}",
            runtime.assignments,
        ),
        &[],
    )
    .context("Go workspace relocation exceeds its command bound")?;
    let output = probe(&query, invocation_root, deadline).await?;
    ensure!(
        output.is_empty(),
        "Go workspace editor returned unexpected output"
    );
    Ok(format!("export GOWORK={copy}; "))
}

/// A private external directory serves both the Go workspace copy/sums and
/// the fresh output stage. Its fixed filenames are removed by the same owned
/// process on success, build failure, or signal; none are source inputs.
fn build_temporary_directory(
    source_ancestors: usize,
    coverage: Option<&GoCoverageCapture>,
) -> String {
    let source = ancestor_path(source_ancestors);
    let report = coverage.map_or_else(String::new, |capture| {
        format!(
            "printf \"\\nRCH_GO_COVERAGE_V1 {} %s %s\\n\" \
             \"$rch_go_final_status\" \"$rch_go_report_state\" >&2 || exit 113; ",
            capture.token
        )
    });
    format!(
        "rch_go_build=; rch_go_stage=; rch_go_report_state=absent; \
         trap 'rch_go_final_status=$?; if [ -n \"$rch_go_build\" ]; then \
           rm -f \"$rch_go_build/output\" \"$rch_go_build/selection.work\" \
           \"$rch_go_build/selection.work.sum\" \"$rch_go_build/vendor\"; rmdir \"$rch_go_build\"; fi; \
           if [ -n \"$rch_go_stage\" ]; then rm -f \"$rch_go_stage/output\"; rmdir \"$rch_go_stage\"; fi; {report}' EXIT; \
         trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
         rch_go_root=$(CDPATH= cd -P {source} && pwd -P) || exit 113; \
         rch_go_created=$(mktemp -d \"${{TMPDIR:-/tmp}}/rch-go-build.XXXXXXXXXX\") || exit 113; \
         rch_go_build=$rch_go_created; \
         rch_go_build_root=$(cd \"$rch_go_build\" && pwd -P) || exit 113; \
         case \"$rch_go_build_root/\" in \"${{rch_go_root%/}}/\"*) \
           printf '%s\\n' 'RCH: Go build temporary directory must be outside the source root' >&2; exit 113;; esac; "
    )
}

pub(in crate::hook) fn go_source_execution_command(
    command: &str,
    invocation_root: &Path,
    source_root: &Path,
    plan: &GoSourcePlan,
    managed_runtime: &BTreeMap<String, String>,
) -> Result<String> {
    source_packages(command).context("Go command lost its admitted source grammar")?;
    let args =
        compiler_arguments(command, &["go"]).context("Go command lost its literal arguments")?;
    let guard = GoSourceGuard::new(plan, invocation_root)?;
    let depth = source_ancestor_depth(invocation_root, source_root)?;
    let runtime = managed_runtime_assignments(Some(managed_runtime))
        .context("Go command lost its managed runtime")?;
    shell_command(
        command,
        format!(
            "{runtime}{}{}export GOWORK=off; {}{}\"$rch_go\" \"$@\"",
            build_temporary_directory(depth, None),
            capture_function(),
            module_cache_check(depth),
            guard.worker_setup(),
        ),
        &args,
    )
    .context("Go source execution guard exceeds its command bound")
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

/// `go test -c` succeeds without producing a binary for a package with no
/// tests. Admit exactly one package that really has test inputs, then require
/// the worker to observe the same selection before creating an output stage.
#[derive(Clone, Debug)]
struct TestPackageWitness {
    record: String,
    implicit: Option<ImplicitTestOutput>,
}

#[derive(Clone, Debug)]
struct ImplicitTestOutput {
    name: String,
    module_mode: bool,
}

impl TestPackageWitness {
    fn parse(bytes: &[u8], implicit: bool) -> Result<Self> {
        let record = std::str::from_utf8(bytes).context("non-UTF-8 Go test package discovery")?;
        let fields: Vec<_> = record
            .strip_suffix('\n')
            .context("unterminated Go test package discovery")?
            .split('\n')
            .collect();
        ensure!(
            fields.len() == if implicit { 5 } else { 3 },
            "Go test output requires exactly one complete package selection"
        );
        let import_path = fields[usize::from(implicit)];
        ensure!(
            !import_path.is_empty() && !import_path.chars().any(char::is_control),
            "Go test output requires a complete package import path"
        );
        let mut test_files = 0_u64;
        for field in &fields[if implicit { 3 } else { 1 }..] {
            let count = field.parse::<u32>().context("invalid Go test file count")?;
            ensure!(
                count.to_string() == *field,
                "non-canonical Go test file count"
            );
            test_files += u64::from(count);
        }
        ensure!(test_files > 0, "Go package has no test binary to deliver");
        let implicit = if implicit {
            let module_mode = match fields[0] {
                "on" => true,
                "off" => false,
                _ => anyhow::bail!("invalid Go package module mode"),
            };
            ensure!(
                !fields[2].is_empty() && !fields[2].chars().any(char::is_control),
                "Go test package has no complete declared name"
            );
            // Match cmd/go's testBinaryName and DefaultExecName rules using
            // the compiler's selected package, never the checkout directory
            // or source filename. Named .go files use their package name;
            // a module-aware import ending in /vN uses the preceding element.
            let base = if import_path == "command-line-arguments" {
                fields[2]
            } else {
                let (parent, last) = import_path.rsplit_once('/').unwrap_or(("", import_path));
                let version = last.strip_prefix('v').is_some_and(|digits| {
                    !digits.is_empty()
                        && !digits.starts_with('0')
                        && digits != "1"
                        && digits.bytes().all(|byte| byte.is_ascii_digit())
                });
                if module_mode && !parent.is_empty() && version {
                    parent
                        .rsplit('/')
                        .next()
                        .context("Go import path has no test basename")?
                } else {
                    last
                }
            };
            ensure!(
                !base.is_empty()
                    && Path::new(base).components().count() == 1
                    && matches!(
                        Path::new(base).components().next(),
                        Some(Component::Normal(_))
                    ),
                "Go package has no supported test executable basename"
            );
            let name = format!("{base}.test");
            ensure!(
                NativeOutputContract::from_paths([name.clone()]).is_some(),
                "Go package has no supported test executable filename"
            );
            Some(ImplicitTestOutput { name, module_mode })
        } else {
            None
        };
        Ok(Self {
            record: record.to_owned(),
            implicit,
        })
    }

    fn worker_check(&self) -> String {
        let expected = shell_escape::escape(self.record.as_str().into());
        format!(
            "if [ \"$rch_go_package\" != {expected} ]; then \
             printf '%s\\n' 'RCH: worker Go test package selection differs from the dispatcher' >&2; exit 113; fi; "
        )
    }
}

/// The caller's effective compiler settings and exact promised file. Recovery
/// persists only the output contract; it never reruns discovery or compilation.
#[derive(Clone, Debug)]
pub(in crate::hook) struct GoBuildEnvironment {
    mode: GoCompileMode,
    settings: String,
    output: NativeOutputContract,
    implicit: Option<PackageWitness>,
    test_package: Option<TestPackageWitness>,
    source_ancestors: usize,
    source: Option<GoSourceGuard>,
    coverage: Option<GoCoverageCapture>,
}

impl GoBuildEnvironment {
    pub(in crate::hook) fn output_contract(&self) -> NativeOutputContract {
        self.output.clone()
    }

    pub(in crate::hook) fn coverage_capture(&self) -> Option<GoCoverageCapture> {
        self.coverage.clone()
    }
}

pub(super) fn invocation(command: &str) -> Option<GoCompileInvocation> {
    let args = compiler_arguments(command, &["go"])?;
    let plain = shell_words::join(std::iter::once("go").chain(args.iter().map(String::as_str)));
    if let Some(invocation) = rch_common::patterns::go_build_invocation(&plain) {
        Some(GoCompileInvocation {
            mode: GoCompileMode::Build,
            output: invocation.output,
            build_flags: invocation.build_flags,
            packages: invocation.packages,
        })
    } else if let Some(invocation) = rch_common::patterns::go_test_invocation(&plain) {
        Some(GoCompileInvocation {
            mode: GoCompileMode::Test,
            output: invocation.output,
            build_flags: invocation.build_flags,
            packages: invocation.packages,
        })
    } else {
        let invocation = rch_common::patterns::go_coverage_invocation(&plain)?;
        Some(GoCompileInvocation {
            mode: GoCompileMode::Coverage,
            output: Some(invocation.output),
            build_flags: invocation.test_flags,
            packages: invocation.packages,
        })
    }
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
           printf '%s\\n' 'RCH: Go output discovery does not support workspace mode' >&2; exit 113;; esac; \
         {caches}"
    )
}

fn package_query(invocation: &GoCompileInvocation, workspace: bool) -> String {
    let implicit_test = invocation.mode == GoCompileMode::Test && invocation.output.is_none();
    let mut args = vec!["list".to_owned()];
    args.extend_from_slice(&invocation.build_flags);
    // These are query-only options. Preserve all package-selection flags,
    // including explicit readonly/vendor and the compiler's auto-vendor mode.
    // VCS stamping cannot affect the package's name or default filename.
    args.extend([
        "-find".to_owned(),
        "-buildvcs=false".to_owned(),
        "-f".to_owned(),
        match invocation.mode {
            GoCompileMode::Build => PACKAGE_FORMAT,
            GoCompileMode::Test if implicit_test => IMPLICIT_TEST_PACKAGE_FORMAT,
            GoCompileMode::Test | GoCompileMode::Coverage => TEST_PACKAGE_FORMAT,
        }
        .to_owned(),
    ]);
    args.extend_from_slice(&invocation.packages);
    let query = shell_words::join(args);
    let module_mode = if implicit_test {
        let empty = shell_escape::escape("\n".into());
        let enabled = shell_escape::escape("on\n".into());
        let disabled = shell_escape::escape("off\n".into());
        // GO111MODULE=auto is not an effective mode. GOMOD is empty only
        // when module mode is disabled; /dev/null still means enabled. The
        // absolute module filename is placement, not part of the witness.
        let work = if workspace { "" } else { "GOWORK=off " };
        format!(
            "{work}rch_go_capture \"$rch_go\" env GOMOD || exit 113; \
             case \"$rch_go_capture_output\" in {empty}) \
               rch_go_module_mode={disabled}; rch_go_module_setting=off;; \
               *) rch_go_read_path || exit 113; \
               rch_go_module_mode={enabled}; rch_go_module_setting=on;; esac; "
        )
    } else {
        String::new()
    };
    let record = if implicit_test {
        "${rch_go_module_mode}${rch_go_capture_output}"
    } else {
        "$rch_go_capture_output"
    };
    let module_environment = if implicit_test {
        "GO111MODULE=\"$rch_go_module_setting\" "
    } else {
        ""
    };
    let work = if workspace { "" } else { "GOWORK=off " };
    format!(
        "{module_mode}{module_environment}GOCACHE=off {work}rch_go_capture \"$rch_go\" {query} || exit 113; \
         rch_go_package=\"{record}\"; "
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
#[cfg(test)]
pub(in crate::hook) async fn validate_go_build_output(
    command: &str,
    project_root: &Path,
    source_root: &Path,
) -> Result<GoBuildEnvironment> {
    validate_go_build_output_in_source(command, project_root, source_root, None).await
}

pub(in crate::hook) async fn validate_go_build_output_in_source(
    command: &str,
    project_root: &Path,
    source_root: &Path,
    source_plan: Option<&GoSourcePlan>,
) -> Result<GoBuildEnvironment> {
    let invocation = invocation(command).context("Go build has no supported output contract")?;
    let runtime = LocalProbeRuntime::create(source_root)?;
    let needs_package_query = invocation.output.is_none() || invocation.mode == GoCompileMode::Test;
    let source_ancestors = if needs_package_query || source_plan.is_some() {
        source_ancestor_depth(project_root, source_root)?
    } else {
        0
    };
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let workspace_environment = if let Some(plan) = source_plan {
        local_workspace_environment(command, project_root, plan, &runtime, deadline).await?
    } else {
        String::new()
    };
    let workspace = source_plan.is_some_and(|plan| plan.workspace.is_some());
    let query = shell_words::join(GO_BUILD_ENVIRONMENT);
    let initial_paths = if needs_package_query || source_plan.is_some() {
        // Toolchain startup may download into GOMODCACHE before executing
        // `go env`. Inspect its placement with GOTOOLCHAIN=local first; the
        // subsequent settings probe still selects the caller's real toolchain.
        format!(
            "{}{}",
            capture_function(),
            if source_plan.is_some() {
                module_cache_check(source_ancestors)
            } else {
                package_query_preflight(source_ancestors)
            }
        )
    } else {
        String::new()
    };
    let environment_command = shell_command(
        command,
        format!(
            "{}{workspace_environment}{initial_paths}\"$rch_go\" env -json {query}",
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
    let package_record = if needs_package_query {
        ensure!(
            readonly_package_discovery_supported(&values["GOVERSION"]),
            "Go output discovery requires a release Go toolchain version 1.18 or newer"
        );
        let script = format!(
            "{}{workspace_environment}{}{}{}{}printf '%s' \"$rch_go_package\"",
            runtime.assignments,
            capture_function(),
            if source_plan.is_some() {
                module_cache_check(source_ancestors)
            } else {
                package_query_preflight(source_ancestors)
            },
            environment_check(&settings),
            package_query(&invocation, workspace),
        );
        let query_command = shell_command(command, script, &[])
            .context("Go package query exceeds its command bound")?;
        Some(probe(&query_command, project_root, deadline).await?)
    } else {
        None
    };
    let test_package = if invocation.mode == GoCompileMode::Test {
        Some(TestPackageWitness::parse(
            package_record
                .as_deref()
                .context("Go test compilation requires package discovery")?,
            invocation.output.is_none(),
        )?)
    } else {
        None
    };
    let (output, implicit) = if let Some(output) = &invocation.output {
        (
            NativeOutputContract::from_paths([output.path.clone()])
                .context("invalid explicit Go file output")?,
            None,
        )
    } else if let Some(witness) = test_package
        .as_ref()
        .and_then(|package| package.implicit.as_ref())
    {
        (
            NativeOutputContract::from_paths([witness.name.clone()])
                .context("invalid implicit Go test executable")?,
            None,
        )
    } else {
        let witness = PackageWitness::parse(
            package_record
                .as_deref()
                .context("implicit Go output requires package discovery")?,
        )?;
        let output = NativeOutputContract::from_paths([witness.output.clone()])
            .context("invalid implicit Go file output")?;
        (output, Some(witness))
    };
    validate_destination(project_root, &output)?;
    if invocation.mode == GoCompileMode::Coverage {
        let parent = output
            .required_files
            .first()
            .and_then(|path| path.parent())
            .context("Go coverage output has no parent")?;
        ensure!(
            project_root.join(parent).is_dir(),
            "Go coverage output parent does not exist"
        );
    }
    let environment = GoBuildEnvironment {
        mode: invocation.mode,
        settings,
        output,
        implicit,
        test_package,
        source_ancestors,
        source: source_plan
            .map(|plan| GoSourceGuard::new(plan, project_root))
            .transpose()?,
        coverage: (invocation.mode == GoCompileMode::Coverage).then(|| GoCoverageCapture {
            token: uuid::Uuid::new_v4().simple().to_string(),
            outcome: None,
        }),
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
    if invocation.mode != environment.mode
        || (invocation.mode == GoCompileMode::Test) != environment.test_package.is_some()
        || (invocation.mode == GoCompileMode::Test && environment.implicit.is_some())
        || (invocation.mode == GoCompileMode::Coverage) != environment.coverage.is_some()
    {
        return None;
    }
    if let Some(capture) = &environment.coverage {
        capture.validate(None).ok()?;
        if capture.present().is_some() || capture.rejection().is_some() {
            return None;
        }
    }
    match (&invocation.output, &environment.implicit) {
        (Some(selection), None)
            if NativeOutputContract::from_paths([selection.path.clone()])?
                == environment.output => {}
        (None, Some(_)) => {}
        (None, None) if invocation.mode == GoCompileMode::Test => {
            let witness = environment.test_package.as_ref()?.implicit.as_ref()?;
            if NativeOutputContract::from_paths([witness.name.clone()])? != environment.output {
                return None;
            }
        }
        _ => return None,
    }
    if environment
        .test_package
        .as_ref()
        .is_some_and(|package| package.implicit.is_some() != invocation.output.is_none())
    {
        return None;
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
    let workspace = environment
        .source
        .as_ref()
        .is_some_and(|source| source.workspace.is_some());
    if let Some(source) = &environment.source {
        // The caller may spell GOWORK as a dispatcher absolute path. Cache
        // admission does not depend on it; source proof installs the exact
        // relocated workspace before querying compiler/package settings.
        preflight.push_str("export GOWORK=off; ");
        preflight.push_str(&module_cache_check(environment.source_ancestors));
        preflight.push_str(&source.worker_setup());
    } else if environment.implicit.is_some() || environment.test_package.is_some() {
        // Cheap path admission precedes costly CGO environment probes. A
        // source-local module cache is refused without warming any cache.
        preflight.push_str(&package_query_preflight(environment.source_ancestors));
    }
    preflight.push_str(&environment_check(&environment.settings));
    let build_environment = if let Some(witness) = &environment.implicit {
        preflight.push_str(&package_query(&invocation, workspace));
        preflight.push_str(&witness.worker_check());
        // Freeze the no-workspace mode just admitted by both sides. A new
        // ancestor go.work between discovery and compilation cannot silently
        // change selection or cause a supposedly readonly query to write sums.
        if workspace { "" } else { "GOWORK=off " }
    } else if let Some(witness) = &environment.test_package {
        preflight.push_str(&package_query(&invocation, workspace));
        preflight.push_str(&witness.worker_check());
        match witness.implicit.as_ref().map(|output| output.module_mode) {
            Some(true) if workspace => "GO111MODULE=on ",
            Some(true) => "GOWORK=off GO111MODULE=on ",
            Some(false) => "GOWORK=off GO111MODULE=off ",
            None if workspace => "",
            None => "GOWORK=off ",
        }
    } else {
        ""
    };
    let subcommand = match invocation.mode {
        GoCompileMode::Build => "build -o",
        GoCompileMode::Test => "test -c -o",
        GoCompileMode::Coverage => "test -coverprofile",
    };
    let parent = shell_escape::escape(format!("./{}", output.parent()?.to_str()?).into());
    // These values come from the pipeline's exact granted runtime placement.
    // Bind inside the wrapper-preserving shell: a leading user `env` command
    // must not restore cache/temp paths outside that grant after the pipeline
    // applies its outer environment. Compiler selection and settings remain
    // unchanged, and the actual build keeps its managed cache enabled.
    let runtime = managed_runtime_assignments(managed_runtime)?;
    let temporary =
        build_temporary_directory(environment.source_ancestors, environment.coverage.as_ref());
    let failed_command = if environment.coverage.is_some() {
        // Early compiler failures may have no report. The exit trap records
        // that fact and the caller's previous output remains untouched.
        "if [ \"$rch_go_status\" -ne 0 ] && [ ! -e \"$rch_go_build/output\" ] && [ ! -L \"$rch_go_build/output\" ]; then exit \"$rch_go_status\"; fi; "
    } else {
        "if [ \"$rch_go_status\" -ne 0 ]; then exit \"$rch_go_status\"; fi; "
    };
    let script = format!(
        "{runtime}{temporary}rch_go_check_output() {{ {path_checks} return 0; }}; \
         rch_go_check_output || exit 113; \
         {preflight}\
         {build_environment}\"$rch_go\" {subcommand} \"$rch_go_build/output\" \"$@\"; \
         rch_go_status=$?; \
         {failed_command}\
         if [ -L \"$rch_go_build/output\" ] || [ ! -f \"$rch_go_build/output\" ]; then \
           printf '%s\\n' 'RCH: Go build succeeded without its required output file' >&2; exit 113; fi; \
         rch_go_parent={parent}; \
         rch_go_check_output || exit 113; \
         mkdir -p \"$rch_go_parent\" || exit 113; \
         rch_go_check_output || exit 113; \
         rch_go_stage=$(mktemp -d \"$rch_go_parent/.rch-go-output.XXXXXXXXXX\") || exit 113; \
         cp -p \"$rch_go_build/output\" \"$rch_go_stage/output\" || exit 113; \
         rch_go_check_output || exit 113; \
         mv -f \"$rch_go_stage/output\" {output_text} || exit 113; \
         rch_go_report_state=present; exit \"$rch_go_status\""
    );
    let mut args = invocation.build_flags;
    args.extend(invocation.packages);
    shell_command(command, script, &args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn go_coverage_early_refusals_record_absence_before_compiler_start() {
        for failure in ["output-parent", "temporary-directory"] {
            let base = tempfile::tempdir().unwrap();
            let source = base.path().join("source");
            let runtime = base.path().join("runtime");
            std::fs::create_dir(&source).unwrap();
            if failure == "output-parent" {
                std::fs::write(source.join("reports"), b"parent sentinel").unwrap();
                std::fs::create_dir(&runtime).unwrap();
            } else {
                std::fs::create_dir(source.join("reports")).unwrap();
                std::fs::write(&runtime, b"temporary-parent sentinel").unwrap();
            }
            let capture = GoCoverageCapture {
                token: "a".repeat(32),
                outcome: None,
            };
            let environment = GoBuildEnvironment {
                mode: GoCompileMode::Coverage,
                // Rejection must precede compiler/environment observation.
                settings: "{}".into(),
                output: NativeOutputContract::from_paths(["reports/coverage.out".into()]).unwrap(),
                implicit: None,
                test_package: None,
                source_ancestors: 0,
                source: None,
                coverage: Some(capture.clone()),
            };
            let guarded = go_build_execution_command(
                "go test -coverprofile reports/coverage.out .",
                &environment,
                None,
            )
            .unwrap();
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &guarded])
                .current_dir(&source)
                .env("TMPDIR", &runtime)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(113), "{failure}: {output:?}");
            let mut capture = capture;
            capture.accept(&output.stderr, 113).unwrap();
            assert_eq!(capture.present(), Some(false));
            assert!(
                output.stdout.is_empty(),
                "compiler must not run: {output:?}"
            );
            assert!(!source.join("reports/coverage.out").exists());
            if failure == "output-parent" {
                assert_eq!(
                    std::fs::read(source.join("reports")).unwrap(),
                    b"parent sentinel"
                );
            } else {
                assert_eq!(
                    std::fs::read(&runtime).unwrap(),
                    b"temporary-parent sentinel"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn go_output_cleanup_preserves_status_and_sigkill_cannot_forge_a_receipt() {
        use std::os::unix::process::ExitStatusExt;

        let base = tempfile::tempdir().unwrap();
        let source = base.path().join("source");
        let runtime = base.path().join("runtime");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&runtime).unwrap();
        for shell in ["/bin/sh", "/bin/bash"] {
            for exit in [0, 23, 101] {
                let script = format!("{}exit {exit}", build_temporary_directory(0, None));
                let output = std::process::Command::new(shell)
                    .args(["-c", &script])
                    .current_dir(&source)
                    .env("TMPDIR", &runtime)
                    .output()
                    .unwrap();
                assert_eq!(output.status.code(), Some(exit), "{shell}: {output:?}");
                assert!(
                    output.stdout.is_empty() && output.stderr.is_empty(),
                    "{output:?}"
                );
            }
        }
        let mut capture = GoCoverageCapture {
            token: "a".repeat(32),
            outcome: None,
        };
        let script = format!(
            "{}kill -KILL $$",
            build_temporary_directory(0, Some(&capture))
        );
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .current_dir(&source)
            .env("TMPDIR", &runtime)
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(9), "{output:?}");
        assert!(capture.accept(&output.stderr, 137).is_err());
        assert_eq!(capture.present(), None);
    }

    #[test]
    fn coverage_outcomes_require_one_complete_same_attempt_record() {
        let capture = GoCoverageCapture {
            token: "a".repeat(32),
            outcome: None,
        };
        let present = format!("RCH_GO_COVERAGE_V1 {} 1 present\n", capture.token);
        let absent = format!("RCH_GO_COVERAGE_V1 {} 1 absent\n", capture.token);
        for bad in [
            Vec::new(),
            present.trim_end().as_bytes().to_vec(),
            present.replace(" 1 ", " 0 ").into_bytes(),
            present
                .replace(&capture.token, &"b".repeat(32))
                .into_bytes(),
            format!("{present}{present}").into_bytes(),
            format!("{present}{absent}").into_bytes(),
        ] {
            let mut rejected = capture.clone();
            assert!(rejected.accept(&bad, 1).is_err());
            assert_eq!(rejected.present(), None);
        }
        let mut ready = capture.clone();
        ready
            .accept(
                format!("arbitrary test diagnostics\n{present}").as_bytes(),
                1,
            )
            .unwrap();
        assert_eq!(ready.present(), Some(true));
        assert!(ready.accept(absent.as_bytes(), 1).is_err());
        assert!(ready.validate(Some(0)).is_err());
        let mut missing = capture;
        missing.accept(absent.as_bytes(), 1).unwrap();
        assert_eq!(missing.present(), Some(false));
        assert!(missing.validate(Some(0)).is_err());
    }

    #[test]
    fn source_argument_grammar_preserves_build_values_and_bounds_test_controls() {
        for command in [
            "go build -tags -run ./cmd/server",
            "go test -run TestSelected -count=1 ./...",
            "go test -coverprofile coverage.out ./...",
            "go test ./... -race -timeout 2m",
            "go test -c -p=1 ./server",
            "go vet -tags=selected ./...",
        ] {
            assert!(source_packages(command).is_some(), "{command}");
        }
        for command in [
            "go test -modfile other.mod ./...",
            "go test -overlay=outside.json ./...",
            "go test -exec ./wrapper ./...",
            "go test ./... -args ./outside",
            "go vet -vettool ../tool ./...",
            "go -C ../other test ./...",
        ] {
            assert!(source_packages(command).is_none(), "{command}");
        }
        assert_eq!(
            source_packages("go test -run 'literal -modfile' -tags -run ./..."),
            Some(vec!["./...".into()])
        );
    }

    #[cfg(unix)]
    struct WorkspaceFixture {
        directory: PathBuf,
        source: PathBuf,
        topology: PathTopologyPolicy,
    }

    #[cfg(unix)]
    impl WorkspaceFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
            let source = directory.join("source workspace");
            for directory in ["app/cmd/server", "library with spaces", "helper"] {
                std::fs::create_dir_all(source.join(directory)).unwrap();
            }
            for (path, bytes) in [
                (
                    "selected.work",
                    "go 1.22\nuse (\n ./app\n \"./library with spaces\"\n)\nreplace example.invalid/helper => ./helper\n",
                ),
                // An explicitly selected workspace must win over this ambient
                // ancestor on both dispatcher and relocated worker.
                ("go.work", "go 1.22\nuse ./unselected-absent\n"),
                ("app/go.mod", "module example.invalid/app\ngo 1.22\n"),
                (
                    "library with spaces/go.mod",
                    "module example.invalid/library\ngo 1.22\nrequire example.invalid/helper v0.0.0\nreplace example.invalid/helper => ../unselected-absent\n",
                ),
                ("helper/go.mod", "module example.invalid/helper\ngo 1.22\n"),
                (
                    "helper/helper.go",
                    "package helper\nconst Value = \"workspace-ok\"\n",
                ),
                (
                    "library with spaces/library.go",
                    "package library\nimport \"example.invalid/helper\"\nconst Value = helper.Value\n",
                ),
                (
                    "app/cmd/server/main.go",
                    "package main\nimport (\"fmt\"; \"example.invalid/library\")\nfunc main() { fmt.Println(library.Value) }\n",
                ),
                (
                    "app/cmd/server/main_test.go",
                    "package main\nimport (\"testing\"; \"example.invalid/library\")\nfunc TestSelected(t *testing.T) { if library.Value != \"workspace-ok\" { t.Fatal(library.Value) } }\n",
                ),
            ] {
                std::fs::write(source.join(path), bytes).unwrap();
            }
            let topology = PathTopologyPolicy::new(directory.clone(), directory.join("alias"));
            Self {
                directory,
                source,
                topology,
            }
        }

        fn cwd(&self) -> PathBuf {
            self.source.join("app/cmd/server")
        }

        fn command(&self, args: &[&str]) -> String {
            let mut words: Vec<String> = [
                "env",
                "GOENV=off",
                "GOTOOLCHAIN=local",
                "GOFLAGS=",
                "GOPROXY=off",
                "GOSUMDB=off",
                "GO111MODULE=on",
                "CGO_ENABLED=0",
                "GOMAXPROCS=2",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            words.push(format!(
                "GOWORK={}",
                self.source.join("selected.work").display()
            ));
            words.push(format!(
                "GOMODCACHE={}",
                self.directory.join("caller-modules").display()
            ));
            words.push("go".into());
            words.extend(args.iter().copied().map(str::to_owned));
            shell_words::join(words)
        }

        fn runtime(&self) -> BTreeMap<String, String> {
            [
                "GOCACHE",
                "GOMODCACHE",
                "GOPATH",
                "GOTMPDIR",
                "TMPDIR",
                "TMP",
                "TEMP",
            ]
            .into_iter()
            .map(|key| {
                let path = self.directory.join("worker-runtime").join(key);
                std::fs::create_dir_all(&path).unwrap();
                (key.to_owned(), path.to_str().unwrap().to_owned())
            })
            .collect()
        }

        fn materialize(&self, name: &str, tree: &BTreeMap<PathBuf, Vec<u8>>) -> PathBuf {
            let worker = self.directory.join(name);
            for (path, bytes) in tree {
                let path = worker.join(path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            worker
        }
    }

    #[cfg(unix)]
    fn source_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                if metadata.is_dir() {
                    visit(root, &entry.path(), result);
                } else {
                    assert!(metadata.is_file());
                    result.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        std::fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut result = BTreeMap::new();
        visit(root, root, &mut result);
        result
    }

    #[cfg(unix)]
    async fn run_fixture(command: &str, cwd: &Path) -> std::process::Output {
        let mut process = tokio::process::Command::new("sh");
        process
            .args(["-c", command])
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        tokio::time::timeout(std::time::Duration::from_secs(120), process.output())
            .await
            .expect("Go workspace fixture exceeded its deadline")
            .expect("Go is required for the workspace regression")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_workspace_queries_preserve_source_and_select_exact_nested_outputs() {
        let fixture = WorkspaceFixture::new();
        let before = source_tree(&fixture.source);
        for (arguments, output) in [
            (vec!["build", "-p=1", "."], "server"),
            (vec!["test", "-c", "-p=1"], "server.test"),
            (
                vec!["build", "-p=1", "-o", "out/selected", "."],
                "out/selected",
            ),
        ] {
            let command = fixture.command(&arguments);
            let plan = discover_go_source(&command, &fixture.cwd(), &fixture.topology)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(plan.source_root, fixture.source);
            assert_eq!(plan.workspace, Some(fixture.source.join("selected.work")));
            assert!(
                plan.required_files
                    .contains_key(&fixture.source.join("helper/go.mod"))
            );
            assert!(
                !plan
                    .required_files
                    .contains_key(&fixture.source.join("go.work"))
            );
            let environment = validate_go_build_output_in_source(
                &command,
                &fixture.cwd(),
                &fixture.source,
                Some(&plan),
            )
            .await
            .unwrap();
            assert_eq!(
                environment.output.required_files,
                BTreeSet::from([PathBuf::from(output)])
            );
            let selected: Vec<_> = before.keys().cloned().collect();
            verify_go_source_selection(&plan, &fixture.source, &selected, &fixture.topology)
                .unwrap();
            let omitted: Vec<_> = selected
                .into_iter()
                .filter(|path| path != Path::new("library with spaces/go.mod"))
                .collect();
            assert!(
                verify_go_source_selection(&plan, &fixture.source, &omitted, &fixture.topology)
                    .is_err()
            );
            assert_eq!(
                source_tree(&fixture.source),
                before,
                "Go query mutated source"
            );
        }
        let escaping = fixture.command(&["build", "-o", "out", "../../../../outside.go"]);
        assert!(
            discover_go_source(&escaping, &fixture.cwd(), &fixture.topology)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_standalone_module_closes_relative_replace_inside_owning_repository() {
        let fixture = WorkspaceFixture::new();
        std::fs::create_dir(fixture.source.join(".git")).unwrap();
        std::fs::write(fixture.source.join("app/go.mod"),
            "module example.invalid/app\ngo 1.22\nrequire example.invalid/library v0.0.0\nrequire example.invalid/helper v0.0.0 // indirect\nreplace example.invalid/library => \"../library with spaces\"\nreplace example.invalid/helper => ../helper\n").unwrap();
        let command = format!(
            "{} GOWORK=off go build -p=1 .",
            fixture.command(&[]).strip_suffix("go").unwrap()
        );
        let before = source_tree(&fixture.source);
        let plan = discover_go_source(&command, &fixture.cwd(), &fixture.topology)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plan.source_root, fixture.source);
        assert!(plan.workspace.is_none());
        assert!(
            plan.required_files
                .contains_key(&fixture.source.join("helper/go.mod"))
        );
        // The dependency's own invalid replacement must not alter main-module
        // resolution or trigger an unrelated source transfer.
        let environment = validate_go_build_output_in_source(
            &command,
            &fixture.cwd(),
            &fixture.source,
            Some(&plan),
        )
        .await
        .unwrap();
        assert_eq!(
            environment.output.required_files,
            BTreeSet::from(["server".into()])
        );
        assert_eq!(source_tree(&fixture.source), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn standalone_go_vendor_metadata_must_survive_source_selection() {
        let fixture = WorkspaceFixture::new();
        let app = fixture.source.join("app");
        let cwd = fixture.cwd();
        let command = format!(
            "{} GOWORK=off go test -p=1 ./...",
            fixture.command(&[]).strip_suffix("go").unwrap()
        );
        let absent = discover_go_source(&command, &cwd, &fixture.topology)
            .await
            .unwrap()
            .unwrap();
        let vendor = app.join("vendor");
        std::fs::create_dir(&vendor).unwrap();
        let selected: Vec<_> = source_tree(&app).into_keys().collect();
        assert!(verify_go_source_selection(&absent, &app, &selected, &fixture.topology).is_err());

        std::fs::write(vendor.join("modules.txt"), "").unwrap();
        let present = discover_go_source(&command, &cwd, &fixture.topology)
            .await
            .unwrap()
            .unwrap();
        assert!(verify_go_source_selection(&present, &app, &selected, &fixture.topology).is_err());
        let selected: Vec<_> = source_tree(&app).into_keys().collect();
        verify_go_source_selection(&present, &app, &selected, &fixture.topology).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_workspace_vendor_mode_preserves_metadata_and_refuses_local_relocation() {
        let fixture = WorkspaceFixture::new();
        let vendor = run_fixture(&fixture.command(&["work", "vendor"]), &fixture.source).await;
        assert!(vendor.status.success(), "{vendor:?}");
        let command = fixture.command(&["build", "-p=1", "."]);
        let error = discover_go_source(&command, &fixture.cwd(), &fixture.topology)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("vendor"), "{error:#}");

        // Pure workspace members keep their ordinary vendoring semantics:
        // unlike replacement paths, use paths do not enter modules.txt.
        let plain = WorkspaceFixture::new();
        std::fs::write(
            plain.source.join("selected.work"),
            "go 1.22\nuse (\n ./app\n \"./library with spaces\"\n ./helper\n)\n",
        )
        .unwrap();
        std::fs::write(
            plain.source.join("library with spaces/go.mod"),
            "module example.invalid/library\ngo 1.22\n",
        )
        .unwrap();
        let vendor = run_fixture(&plain.command(&["work", "vendor"]), &plain.source).await;
        assert!(vendor.status.success(), "{vendor:?}");
        let before = source_tree(&plain.source);
        for arguments in [
            vec!["build", "-p=1", "."],
            vec!["build", "-p=1", "-mod=vendor", "."],
        ] {
            let command = plain.command(&arguments);
            let plan = discover_go_source(&command, &plain.cwd(), &plain.topology)
                .await
                .unwrap()
                .unwrap();
            assert!(
                plan.required_files
                    .contains_key(&plain.source.join("vendor/modules.txt"))
            );
            let environment = validate_go_build_output_in_source(
                &command,
                &plain.cwd(),
                &plain.source,
                Some(&plan),
            )
            .await
            .unwrap();
            assert_eq!(
                environment.output.required_files,
                BTreeSet::from(["server".into()])
            );
            assert_eq!(
                source_tree(&plain.source),
                before,
                "vendoring query changed source"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires Go and a compiled rch-wkr via RCH_WKR_BIN"]
    async fn real_go_relocated_workspace_executes_and_refuses_stale_worker_metadata() {
        assert!(
            std::env::var_os("RCH_WKR_BIN").is_some(),
            "set RCH_WKR_BIN to the native worker verifier"
        );
        let fixture = WorkspaceFixture::new();
        let before = source_tree(&fixture.source);
        let command = fixture.command(&["build", "-p=1", "."]);
        let plan = discover_go_source(&command, &fixture.cwd(), &fixture.topology)
            .await
            .unwrap()
            .unwrap();
        let environment = validate_go_build_output_in_source(
            &command,
            &fixture.cwd(),
            &fixture.source,
            Some(&plan),
        )
        .await
        .unwrap();
        let runtime = fixture.runtime();
        let guarded = go_build_execution_command(&command, &environment, Some(&runtime)).unwrap();
        let worker = fixture.materialize("relocated worker", &before);
        let cwd = worker.join("app/cmd/server");
        // A surviving dispatcher absolute workspace/member path would read
        // this later edit instead of the bytes already materialized remotely.
        std::fs::write(
            fixture.source.join("helper/helper.go"),
            "package helper\nconst Value = \"wrong-dispatcher-source\"\n",
        )
        .unwrap();
        let built = run_fixture(&guarded, &cwd).await;
        assert!(built.status.success(), "{built:?}");
        let binary = run_fixture("./server", &cwd).await;
        assert_eq!(binary.stdout, b"workspace-ok\n");
        environment.output.verify_staged(&cwd).unwrap();
        for arguments in [
            vec!["test", "-p=1", "-run", "TestSelected", "-count=1", "./..."],
            vec!["vet", "-p=1", "./..."],
        ] {
            let command = fixture.command(&arguments);
            let guarded = go_source_execution_command(
                &command,
                &fixture.cwd(),
                &fixture.source,
                &plan,
                &runtime,
            )
            .unwrap();
            let output = run_fixture(&guarded, &cwd).await;
            assert!(output.status.success(), "{arguments:?}: {output:?}");
        }
        let test = fixture.command(&["test", "-c", "-p=1"]);
        let test_environment =
            validate_go_build_output_in_source(&test, &fixture.cwd(), &fixture.source, Some(&plan))
                .await
                .unwrap();
        let test_command =
            go_build_execution_command(&test, &test_environment, Some(&runtime)).unwrap();
        let compiled = run_fixture(&test_command, &cwd).await;
        assert!(compiled.status.success(), "{compiled:?}");
        assert!(run_fixture("./server.test", &cwd).await.status.success());
        let mut expected = before.clone();
        let worker_tree = source_tree(&worker);
        for output in ["app/cmd/server/server", "app/cmd/server/server.test"] {
            expected.insert(
                output.into(),
                worker_tree.get(Path::new(output)).unwrap().clone(),
            );
        }
        assert_eq!(
            worker_tree, expected,
            "workspace execution changed source controls"
        );
        for (name, relative, contents) in [
            (
                "changed-control",
                "helper/go.mod",
                "module example.invalid/changed\ngo 1.22\n",
            ),
            ("stale-sum", "selected.work.sum", "stale-worker-only-sum\n"),
            (
                "nested-module",
                "app/cmd/server/go.mod",
                "module example.invalid/unselected\ngo 1.22\n",
            ),
        ] {
            let worker = fixture.materialize(name, &before);
            std::fs::write(worker.join(relative), contents).unwrap();
            let cwd = worker.join("app/cmd/server");
            std::fs::write(cwd.join("server"), b"old output must survive refusal").unwrap();
            let output = run_fixture(&guarded, &cwd).await;
            assert_eq!(output.status.code(), Some(113), "{name}: {output:?}");
            assert_eq!(
                std::fs::read(cwd.join("server")).unwrap(),
                b"old output must survive refusal"
            );
        }
    }

    #[test]
    fn test_package_witness_requires_one_package_with_actual_test_inputs() {
        for record in [
            "example.invalid/library\n1\n0\n",
            "example.invalid/library\n0\n2\n",
            "command-line-arguments\n1\n1\n",
        ] {
            let witness = TestPackageWitness::parse(record.as_bytes(), false).unwrap();
            assert_eq!(witness.record, record);
            assert!(witness.implicit.is_none());
        }
        for record in [
            "example.invalid/library\n0\n0\n",
            "\n1\n0\n",
            "example.invalid/lib\rary\n1\n0\n",
            "example.invalid/library\n1\n0",
            "example.invalid/library\n01\n0\n",
            "example.invalid/library\n-1\n0\n",
            "example.invalid/library\n4294967296\n0\n",
            "example.invalid/library\n1\n0\n\n",
            "example.invalid/library\n1\n0\nexample.invalid/other\n1\n0\n",
        ] {
            assert!(
                TestPackageWitness::parse(record.as_bytes(), false).is_err(),
                "{record:?}"
            );
        }
    }

    #[test]
    fn implicit_test_witness_uses_compiler_package_and_effective_module_mode() {
        for (mode, import_path, package, expected) in [
            ("on", "example.invalid/library", "different", "library.test"),
            ("on", "example.invalid/tool", "main", "tool.test"),
            ("on", "command-line-arguments", "fixture", "fixture.test"),
            ("off", "command-line-arguments", "main", "main.test"),
            (
                "on",
                "example.invalid/library/v2",
                "library",
                "library.test",
            ),
            (
                "on",
                "example.invalid/library/v10",
                "library",
                "library.test",
            ),
            ("off", "example.invalid/library/v2", "library", "v2.test"),
            ("on", "example.invalid/library/v1", "library", "v1.test"),
            ("on", "example.invalid/library/v0", "library", "v0.test"),
            ("on", "example.invalid/library/v02", "library", "v02.test"),
            ("on", "example.invalid/library/v2x", "library", "v2x.test"),
            ("on", "v2", "library", "v2.test"),
        ] {
            let record = format!("{mode}\n{import_path}\n{package}\n1\n0\n");
            let witness = TestPackageWitness::parse(record.as_bytes(), true).unwrap();
            assert_eq!(witness.record, record);
            let implicit = witness.implicit.unwrap();
            assert_eq!(implicit.name, expected, "{record:?}");
            assert_eq!(implicit.module_mode, mode == "on");
        }
        for record in [
            "on\nexample.invalid/library\nfixture\n0\n0\n",
            "auto\nexample.invalid/library\nfixture\n1\n0\n",
            "on\nexample.invalid/library\n\n1\n0\n",
            "on\nexample.invalid/library\nfixt\rure\n1\n0\n",
            "on\ncommand-line-arguments\n../outside\n1\n0\n",
            "on\nexample.invalid/../v2\nfixture\n1\n0\n",
            "on\nexample.invalid/library\nfixture\n1\n0",
            "on\nexample.invalid/library\nfixture\n01\n0\n",
            "on\nexample.invalid/library\nfixture\n1\n0\nexample.invalid/other\nother\n1\n0\n",
            "example.invalid/library\n1\n0\n",
        ] {
            assert!(
                TestPackageWitness::parse(record.as_bytes(), true).is_err(),
                "{record:?}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn worker_implicit_test_witness_rejects_changed_module_mode_or_package_name() {
        let witness =
            TestPackageWitness::parse(b"on\nexample.invalid/library/v2\nfixture\n1\n0\n", true)
                .unwrap();
        for (record, admitted) in [
            ("on\nexample.invalid/library/v2\nfixture\n1\n0\n", true),
            ("off\nexample.invalid/library/v2\nfixture\n1\n0\n", false),
            ("on\nexample.invalid/library/v2\nmain\n1\n0\n", false),
            ("on\nexample.invalid/library/v3\nfixture\n1\n0\n", false),
            ("on\nexample.invalid/library/v2\nfixture\n0\n0\n", false),
            ("on\nexample.invalid/library/v2\nfixture\n1\n0", false),
        ] {
            let record = shell_escape::escape(record.into());
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
    fn worker_test_witness_refuses_changed_or_incomplete_package_selection() {
        let witness = TestPackageWitness::parse(b"example.invalid/library\n1\n1\n", false).unwrap();
        for (record, admitted) in [
            ("example.invalid/library\n1\n1\n", true),
            ("example.invalid/library\n1\n1", false),
            ("example.invalid/library\n0\n0\n", false),
            ("example.invalid/library\n2\n0\n", false),
            ("example.invalid/other\n1\n1\n", false),
            ("example.invalid/library\n1\n1\nextra\n", false),
        ] {
            let record = shell_escape::escape(record.into());
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
