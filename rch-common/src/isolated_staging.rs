//! Invocation-owned Linux source layout and receiver admission (GH #104).
//!
//! This is a staging backend, NOT an enabled ordinary-exec route. Orchestration
//! must supply the complete canonical dependency closure, hold its existing
//! durable source grant around receivers/build/retrieval, and persist this
//! layout before writing remote state. Recovery verifies that same invocation;
//! it must not generate a new identity or replay an uncertain build.
//!
//! Mapping retains the full POSIX hierarchy under one private source container,
//! preserving relative relationships between roots, nested working directories,
//! and project-relative artifact locations. It does not rewrite absolute paths
//! embedded in manifests, commands, environment variables, or source symlinks.
//! Such references need a separate proven remapping/namespace policy before an
//! ordinary build can use this backend. Caches containing compiler-visible paths
//! must include `source_container()` in their identity; do not blindly attach a
//! canonical-path target pool to an invocation-isolated source tree.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const ISOLATED_STAGING_SCRIPT: &str = include_str!("isolated_staging.sh");
const LAYOUT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingError(String);

impl fmt::Display for StagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StagingError {}

fn refused(message: impl Into<String>) -> StagingError {
    StagingError(message.into())
}

/// Journal only canonical inputs; never deserialize unchecked remote paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutWire {
    version: u32,
    remote_base: String,
    invocation: String,
    primary_root: String,
    working_directory: String,
    roots: Vec<String>,
}

/// Immutable, validated layout. The invocation is a fresh UUID's 32-character
/// lowercase hexadecimal representation, supplied by the existing recovery ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LayoutWire", into = "LayoutWire")]
pub struct IsolatedStagingLayout {
    remote_base: String,
    invocation: String,
    primary_root: String,
    working_directory: String,
    roots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMapping {
    pub remote_path: String,
    pub local_path: String,
}

impl IsolatedStagingLayout {
    pub fn new(
        remote_base: &str,
        invocation: &str,
        primary_root: &str,
        working_directory: &str,
        roots: impl IntoIterator<Item = String>,
    ) -> Result<Self, StagingError> {
        validate_absolute(remote_base)?;
        validate_absolute(primary_root)?;
        validate_absolute(working_directory)?;
        if invocation.len() != 32
            || !invocation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refused(
                "invocation must be 32 lowercase hexadecimal characters",
            ));
        }
        let mut unique = BTreeSet::new();
        for root in roots {
            validate_absolute(&root)?;
            if contains_path(&root, remote_base) || contains_path(remote_base, &root) {
                return Err(refused("staging base overlaps the source closure"));
            }
            unique.insert(root);
        }
        if unique.is_empty() {
            return Err(refused("source closure is empty"));
        }
        if !unique.contains(primary_root) {
            return Err(refused("primary root is absent from the source closure"));
        }
        if !contains_path(primary_root, working_directory) {
            return Err(refused("working directory is outside the primary root"));
        }
        Ok(Self {
            remote_base: remote_base.to_owned(),
            invocation: invocation.to_owned(),
            primary_root: primary_root.to_owned(),
            working_directory: working_directory.to_owned(),
            roots: unique.into_iter().collect(),
        })
    }

    pub fn invocation_root(&self) -> String {
        format!("{}/invocations/{}", self.remote_base, self.invocation)
    }

    pub fn source_container(&self) -> String {
        format!("{}/source", self.invocation_root())
    }

    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// Map only paths inside a declared root, with component-boundary checks.
    pub fn remote_path(&self, local_path: &str) -> Result<String, StagingError> {
        validate_absolute(local_path)?;
        if !self
            .roots
            .iter()
            .any(|root| contains_path(root, local_path))
        {
            return Err(refused("path is outside the declared source closure"));
        }
        Ok(format!("{}{local_path}", self.source_container()))
    }

    pub fn remote_working_directory(&self) -> String {
        format!("{}{}", self.source_container(), self.working_directory)
    }

    /// Reverse mapping for diagnostics. Do not accept a neighboring invocation
    /// or an undeclared sibling simply because it shares a textual prefix.
    pub fn local_path(&self, remote_path: &str) -> Result<String, StagingError> {
        validate_absolute(remote_path)?;
        let container = self.source_container();
        let local = remote_path
            .strip_prefix(&container)
            .ok_or_else(|| refused("remote path belongs to another source container"))?;
        self.remote_path(local)?;
        Ok(local.to_owned())
    }

    pub fn artifact_mapping(&self, relative: &str) -> Result<ArtifactMapping, StagingError> {
        validate_relative(relative)?;
        let local_path = format!("{}/{relative}", self.primary_root);
        Ok(ArtifactMapping {
            remote_path: self.remote_path(&local_path)?,
            local_path,
        })
    }

    /// Atomically claim a fresh invocation. Never call this to resume recovery.
    pub fn prepare_command(&self) -> String {
        shell_call("rch_stage_prepare", &[&self.remote_base, &self.invocation])
    }

    /// Read-only owner/path verification; NOT proof that a previous process or
    /// source writer has stopped. The durable lease protocol remains authority.
    pub fn verify_command(&self, root: &str) -> Result<String, StagingError> {
        let remote = self.declared_remote_root(root)?;
        Ok(shell_call(
            "rch_stage_verify",
            &[&self.remote_base, &self.invocation, &remote],
        ))
    }

    /// Pass to rsync's --rsync-path for SOURCE UPLOAD only. rsync appends its
    /// server argv; the receiver validates and pins the exact planned target.
    /// The existing checkout fence/source lease must still wrap this command.
    pub fn receiver_command(&self, root: &str) -> Result<String, StagingError> {
        let remote = self.declared_remote_root(root)?;
        Ok(shell_call(
            "rch_stage_receive",
            &[&self.remote_base, &self.invocation, &remote],
        ))
    }

    fn declared_remote_root(&self, root: &str) -> Result<String, StagingError> {
        if !self.roots.iter().any(|declared| declared == root) {
            return Err(refused("receiver root is not a declared closure root"));
        }
        self.remote_path(root)
    }
}

impl TryFrom<LayoutWire> for IsolatedStagingLayout {
    type Error = StagingError;

    fn try_from(value: LayoutWire) -> Result<Self, Self::Error> {
        if value.version != LAYOUT_VERSION {
            return Err(refused("unsupported isolated staging layout version"));
        }
        Self::new(
            &value.remote_base,
            &value.invocation,
            &value.primary_root,
            &value.working_directory,
            value.roots,
        )
    }
}

impl From<IsolatedStagingLayout> for LayoutWire {
    fn from(value: IsolatedStagingLayout) -> Self {
        Self {
            version: LAYOUT_VERSION,
            remote_base: value.remote_base,
            invocation: value.invocation,
            primary_root: value.primary_root,
            working_directory: value.working_directory,
            roots: value.roots,
        }
    }
}

fn contains_path(root: &str, path: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
}

fn validate_absolute(path: &str) -> Result<(), StagingError> {
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| refused("expected an absolute POSIX path"))?;
    validate_relative(relative)
}

fn validate_relative(path: &str) -> Result<(), StagingError> {
    if path.is_empty()
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(refused(
            "path is empty, non-canonical, or contains control characters",
        ));
    }
    Ok(())
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn shell_call(function: &str, args: &[&str]) -> String {
    // function is an internal constant, never caller-supplied shell grammar.
    let script = format!("{ISOLATED_STAGING_SCRIPT}\n{function} \"$@\"\n");
    let mut command = format!("sh -c {} rch-isolated-stage", quote(&script));
    for arg in args {
        command.push(' ');
        command.push_str(&quote(arg));
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn layout(id: &str) -> IsolatedStagingLayout {
        IsolatedStagingLayout::new(
            "/var/tmp/rch-isolated",
            id,
            "/data/app",
            "/data/app/crates/client",
            [
                "/data/shared".into(),
                "/data/app".into(),
                "/data/app/vendor/nested".into(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn sibling_and_nested_roots_share_one_hierarchy() {
        let layout = layout(ID);
        let base = layout.source_container();
        for root in layout.roots() {
            assert_eq!(layout.remote_path(root).unwrap(), format!("{base}{root}"));
        }
        assert_eq!(
            layout.remote_working_directory(),
            format!("{base}/data/app/crates/client")
        );
        let artifact = layout.artifact_mapping("target/debug/app").unwrap();
        assert_eq!(artifact.local_path, "/data/app/target/debug/app");
        assert_eq!(
            artifact.remote_path,
            format!("{base}/data/app/target/debug/app")
        );
    }

    #[test]
    fn concurrent_invocations_do_not_share_sources() {
        let first = layout(ID);
        let second = layout("fedcba9876543210fedcba9876543210");
        assert_ne!(first.source_container(), second.source_container());
        assert!(
            first
                .local_path(&second.remote_working_directory())
                .is_err()
        );
    }

    #[test]
    fn journal_roundtrip_keeps_recovery_identity() {
        let before = layout(ID);
        let json = serde_json::to_string(&before).unwrap();
        let after: IsolatedStagingLayout = serde_json::from_str(&json).unwrap();
        assert_eq!(before, after);
        assert_eq!(
            before.verify_command("/data/app"),
            after.verify_command("/data/app")
        );
        let bad_version = json.replace("\"version\":1", "\"version\":2");
        assert!(serde_json::from_str::<IsolatedStagingLayout>(&bad_version).is_err());
        let unsafe_base = json.replace("/var/tmp/rch-isolated", "/var/tmp/../data");
        assert!(serde_json::from_str::<IsolatedStagingLayout>(&unsafe_base).is_err());
    }

    #[test]
    fn boundaries_and_artifact_traversal_are_refused() {
        let layout = layout(ID);
        for path in [
            "/data/application",
            "/data/app/../other",
            "/data/app//x",
            "/",
        ] {
            assert!(layout.remote_path(path).is_err(), "{path}");
        }
        for relative in [
            "",
            "../src/main.rs",
            "/etc/passwd",
            "target/../../src",
            "target//x",
        ] {
            assert!(layout.artifact_mapping(relative).is_err(), "{relative}");
        }
        assert!(
            layout
                .receiver_command("/data/app/undeclared-child")
                .is_err()
        );
        assert_eq!(
            layout
                .local_path(&layout.remote_path("/data/shared/src/lib.rs").unwrap())
                .unwrap(),
            "/data/shared/src/lib.rs"
        );
    }

    #[test]
    fn invalid_layouts_are_refused_before_remote_commands() {
        for base in [
            "/",
            "relative",
            "/var//tmp",
            "/var/../tmp",
            "/data",
            "/data/app/cache",
            "/tmp\n",
        ] {
            assert!(
                IsolatedStagingLayout::new(
                    base,
                    ID,
                    "/data/app",
                    "/data/app",
                    ["/data/app".into()],
                )
                .is_err()
            );
        }
        for id in [
            "",
            "abc",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(
                IsolatedStagingLayout::new(
                    "/tmp/stage",
                    id,
                    "/data/app",
                    "/data/app",
                    ["/data/app".into()],
                )
                .is_err()
            );
        }
        assert!(
            IsolatedStagingLayout::new("/tmp/stage", ID, "/data/app", "/data/app", Vec::new())
                .is_err()
        );
        assert!(
            IsolatedStagingLayout::new(
                "/tmp/stage",
                ID,
                "/data/app",
                "/data/application",
                ["/data/app".into()],
            )
            .is_err()
        );
    }

    #[test]
    fn shell_values_are_not_executable_fragments() {
        assert_eq!(quote("x'y;$(id)"), "'x'\\''y;$(id)'");
        let command = layout(ID).receiver_command("/data/app").unwrap();
        assert!(command.contains("rch_stage_receive"));
        assert!(command.ends_with(&quote(&layout(ID).remote_path("/data/app").unwrap())));
    }
}
