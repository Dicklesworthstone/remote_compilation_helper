//! Canonical path topology utilities for host/worker project mapping.
//!
//! This module normalizes project roots to a single canonical namespace so
//! equivalent aliases (for example `/dp` and `/data/projects`) map to one
//! deterministic identity. It also emits structured decision traces to aid
//! troubleshooting when path normalization fails.

use std::fmt;
use std::path::{Path, PathBuf};

/// Canonical root used for project identity and transfer safety checks.
pub const DEFAULT_CANONICAL_PROJECT_ROOT: &str = "/data/projects";

/// Alias root expected to point at [`DEFAULT_CANONICAL_PROJECT_ROOT`].
pub const DEFAULT_ALIAS_PROJECT_ROOT: &str = "/dp";

/// Policy describing canonical and alias roots used for normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTopologyPolicy {
    canonical_root: PathBuf,
    alias_root: PathBuf,
}

impl PathTopologyPolicy {
    /// Create a policy with explicit canonical and alias roots.
    pub fn new(canonical_root: PathBuf, alias_root: PathBuf) -> Self {
        Self {
            canonical_root,
            alias_root,
        }
    }

    /// Canonical root path.
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Alias root path.
    pub fn alias_root(&self) -> &Path {
        &self.alias_root
    }
}

impl Default for PathTopologyPolicy {
    fn default() -> Self {
        Self {
            canonical_root: PathBuf::from(DEFAULT_CANONICAL_PROJECT_ROOT),
            alias_root: PathBuf::from(DEFAULT_ALIAS_PROJECT_ROOT),
        }
    }
}

/// Structured trace for normalization decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationDecision {
    ReceivedInput(PathBuf),
    VerifiedAbsoluteInput(PathBuf),
    AliasPrefixDetected(PathBuf),
    AliasSymlinkVerified {
        alias_root: PathBuf,
        alias_target: PathBuf,
    },
    CanonicalRootResolved(PathBuf),
    CanonicalInputResolved(PathBuf),
    VerifiedWithinCanonicalRoot {
        canonical_path: PathBuf,
        canonical_root: PathBuf,
    },
}

impl fmt::Display for NormalizationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReceivedInput(path) => write!(f, "received_input={}", path.display()),
            Self::VerifiedAbsoluteInput(path) => {
                write!(f, "verified_absolute_input={}", path.display())
            }
            Self::AliasPrefixDetected(alias_root) => {
                write!(f, "alias_prefix_detected={}", alias_root.display())
            }
            Self::AliasSymlinkVerified {
                alias_root,
                alias_target,
            } => write!(
                f,
                "alias_symlink_verified={} -> {}",
                alias_root.display(),
                alias_target.display()
            ),
            Self::CanonicalRootResolved(path) => {
                write!(f, "canonical_root_resolved={}", path.display())
            }
            Self::CanonicalInputResolved(path) => {
                write!(f, "canonical_input_resolved={}", path.display())
            }
            Self::VerifiedWithinCanonicalRoot {
                canonical_path,
                canonical_root,
            } => write!(
                f,
                "verified_within_root={} root={}",
                canonical_path.display(),
                canonical_root.display()
            ),
        }
    }
}

/// Successful normalization result with deterministic canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedProjectPath {
    canonical_path: PathBuf,
    canonical_root: PathBuf,
    used_alias_prefix: bool,
    decisions: Vec<NormalizationDecision>,
}

impl NormalizedProjectPath {
    /// Canonical path for this project root.
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Canonical project root used for containment checks.
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Whether the input path used the alias prefix (for example `/dp`).
    pub fn used_alias_prefix(&self) -> bool {
        self.used_alias_prefix
    }

    /// Structured decision trace for diagnostics.
    pub fn decision_trace(&self) -> &[NormalizationDecision] {
        &self.decisions
    }
}

/// Error class for path normalization failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNormalizationErrorKind {
    NotAbsoluteInput,
    CanonicalRootMissing,
    CanonicalRootResolveFailed,
    AliasMissing,
    AliasNotSymlink,
    AliasReadLinkFailed,
    AliasTargetResolveFailed,
    AliasWrongTarget,
    InputResolveFailed,
    OutsideCanonicalRoot,
}

impl fmt::Display for PathNormalizationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsoluteInput => write!(f, "input path is not absolute"),
            Self::CanonicalRootMissing => write!(f, "canonical root is missing"),
            Self::CanonicalRootResolveFailed => write!(f, "failed to resolve canonical root"),
            Self::AliasMissing => write!(f, "alias root is missing"),
            Self::AliasNotSymlink => write!(f, "alias root is not a symlink"),
            Self::AliasReadLinkFailed => write!(f, "failed to read alias symlink"),
            Self::AliasTargetResolveFailed => write!(f, "failed to resolve alias target"),
            Self::AliasWrongTarget => write!(f, "alias points to unexpected target"),
            Self::InputResolveFailed => write!(f, "failed to resolve input path"),
            Self::OutsideCanonicalRoot => write!(f, "input resolves outside canonical root"),
        }
    }
}

/// Normalization error with structured trace context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNormalizationError {
    kind: PathNormalizationErrorKind,
    input_path: PathBuf,
    detail: String,
    decisions: Vec<NormalizationDecision>,
}

impl PathNormalizationError {
    fn new(
        kind: PathNormalizationErrorKind,
        input_path: &Path,
        detail: impl Into<String>,
        decisions: &[NormalizationDecision],
    ) -> Self {
        Self {
            kind,
            input_path: input_path.to_path_buf(),
            detail: detail.into(),
            decisions: decisions.to_vec(),
        }
    }

    /// Error category.
    pub fn kind(&self) -> &PathNormalizationErrorKind {
        &self.kind
    }

    /// Human-readable detail about the failure.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Structured decision trace for diagnostics.
    pub fn decision_trace(&self) -> &[NormalizationDecision] {
        &self.decisions
    }
}

impl fmt::Display for PathNormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (input: {}, detail: {})",
            self.kind,
            self.input_path.display(),
            self.detail
        )
    }
}

impl std::error::Error for PathNormalizationError {}

/// Normalize a project path using the default `/data/projects` + `/dp` policy.
pub fn normalize_project_path(
    path: &Path,
) -> Result<NormalizedProjectPath, PathNormalizationError> {
    normalize_project_path_with_policy(path, &PathTopologyPolicy::default())
}

/// Normalize a project path with explicit topology policy.
pub fn normalize_project_path_with_policy(
    path: &Path,
    policy: &PathTopologyPolicy,
) -> Result<NormalizedProjectPath, PathNormalizationError> {
    let mut decisions = vec![NormalizationDecision::ReceivedInput(path.to_path_buf())];

    if !path.is_absolute() {
        return Err(PathNormalizationError::new(
            PathNormalizationErrorKind::NotAbsoluteInput,
            path,
            "path must be absolute",
            &decisions,
        ));
    }
    decisions.push(NormalizationDecision::VerifiedAbsoluteInput(
        path.to_path_buf(),
    ));

    let canonical_root = resolve_canonical_root(path, policy, &mut decisions)?;

    let used_alias_prefix = path.starts_with(policy.alias_root());
    if used_alias_prefix {
        decisions.push(NormalizationDecision::AliasPrefixDetected(
            policy.alias_root().to_path_buf(),
        ));
        verify_alias(path, policy.alias_root(), &canonical_root, &mut decisions)?;
    }

    let canonical_input = std::fs::canonicalize(path).map_err(|e| {
        PathNormalizationError::new(
            PathNormalizationErrorKind::InputResolveFailed,
            path,
            e.to_string(),
            &decisions,
        )
    })?;
    decisions.push(NormalizationDecision::CanonicalInputResolved(
        canonical_input.clone(),
    ));

    if !canonical_input.starts_with(&canonical_root) {
        return Err(PathNormalizationError::new(
            PathNormalizationErrorKind::OutsideCanonicalRoot,
            path,
            format!(
                "resolved={} root={}",
                canonical_input.display(),
                canonical_root.display()
            ),
            &decisions,
        ));
    }
    decisions.push(NormalizationDecision::VerifiedWithinCanonicalRoot {
        canonical_path: canonical_input.clone(),
        canonical_root: canonical_root.clone(),
    });

    Ok(NormalizedProjectPath {
        canonical_path: canonical_input,
        canonical_root,
        used_alias_prefix,
        decisions,
    })
}

fn resolve_canonical_root(
    input_path: &Path,
    policy: &PathTopologyPolicy,
    decisions: &mut Vec<NormalizationDecision>,
) -> Result<PathBuf, PathNormalizationError> {
    if !policy.canonical_root().exists() {
        return Err(PathNormalizationError::new(
            PathNormalizationErrorKind::CanonicalRootMissing,
            input_path,
            format!("missing root {}", policy.canonical_root().display()),
            decisions,
        ));
    }

    let canonical_root = std::fs::canonicalize(policy.canonical_root()).map_err(|e| {
        PathNormalizationError::new(
            PathNormalizationErrorKind::CanonicalRootResolveFailed,
            input_path,
            e.to_string(),
            decisions,
        )
    })?;
    decisions.push(NormalizationDecision::CanonicalRootResolved(
        canonical_root.clone(),
    ));
    Ok(canonical_root)
}

fn verify_alias(
    input_path: &Path,
    alias_root: &Path,
    canonical_root: &Path,
    decisions: &mut Vec<NormalizationDecision>,
) -> Result<(), PathNormalizationError> {
    let metadata = std::fs::symlink_metadata(alias_root).map_err(|e| {
        let kind = if e.kind() == std::io::ErrorKind::NotFound {
            PathNormalizationErrorKind::AliasMissing
        } else {
            PathNormalizationErrorKind::AliasReadLinkFailed
        };
        PathNormalizationError::new(kind, input_path, e.to_string(), decisions)
    })?;

    if !metadata.file_type().is_symlink() {
        return Err(PathNormalizationError::new(
            PathNormalizationErrorKind::AliasNotSymlink,
            input_path,
            format!("alias root is not a symlink: {}", alias_root.display()),
            decisions,
        ));
    }

    let raw_target = std::fs::read_link(alias_root).map_err(|e| {
        PathNormalizationError::new(
            PathNormalizationErrorKind::AliasReadLinkFailed,
            input_path,
            e.to_string(),
            decisions,
        )
    })?;
    let absolute_target = if raw_target.is_absolute() {
        raw_target
    } else {
        alias_root
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .join(raw_target)
    };
    let resolved_target = std::fs::canonicalize(&absolute_target).map_err(|e| {
        PathNormalizationError::new(
            PathNormalizationErrorKind::AliasTargetResolveFailed,
            input_path,
            e.to_string(),
            decisions,
        )
    })?;

    if resolved_target != canonical_root {
        return Err(PathNormalizationError::new(
            PathNormalizationErrorKind::AliasWrongTarget,
            input_path,
            format!(
                "expected={} actual={}",
                canonical_root.display(),
                resolved_target.display()
            ),
            decisions,
        ));
    }

    decisions.push(NormalizationDecision::AliasSymlinkVerified {
        alias_root: alias_root.to_path_buf(),
        alias_target: resolved_target,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracing::info;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestFixture {
        root: PathBuf,
        canonical_root: PathBuf,
        alias_root: PathBuf,
    }

    impl TestFixture {
        fn new(prefix: &str, create_alias: bool, alias_target: Option<&Path>) -> Self {
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "rch-path-topology-{}-{}-{}",
                prefix,
                std::process::id(),
                id
            ));
            let canonical_root = root.join("data/projects");
            let alias_root = root.join("dp");

            fs::create_dir_all(&canonical_root).expect("create canonical root");

            #[cfg(unix)]
            if create_alias {
                let target = alias_target.unwrap_or(&canonical_root);
                symlink(target, &alias_root).expect("create alias symlink");
            }

            #[cfg(not(unix))]
            {
                let _ = create_alias;
                let _ = alias_target;
            }

            Self {
                root,
                canonical_root,
                alias_root,
            }
        }

        fn policy(&self) -> PathTopologyPolicy {
            PathTopologyPolicy::new(self.canonical_root.clone(), self.alias_root.clone())
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn log_normalization_error(test_name: &str, err: &PathNormalizationError) {
        info!(
            test = test_name,
            kind = ?err.kind(),
            detail = %err.detail(),
            decisions = ?err.decision_trace(),
            "topology_normalization_error"
        );
    }

    #[test]
    fn normalize_direct_canonical_path() {
        let fixture = TestFixture::new("direct", false, None);
        let project = fixture.canonical_root.join("demo");
        fs::create_dir_all(&project).expect("create project");

        let normalized = normalize_project_path_with_policy(&project, &fixture.policy())
            .expect("normalize canonical path");

        assert_eq!(
            normalized.canonical_path(),
            project.canonicalize().expect("canonicalize project")
        );
        assert!(!normalized.used_alias_prefix());
        assert!(normalized.decision_trace().len() >= 4);
    }

    #[cfg(unix)]
    #[test]
    fn normalize_alias_path_to_same_canonical_identity() {
        let fixture = TestFixture::new("alias", true, None);
        let project = fixture.canonical_root.join("repo");
        fs::create_dir_all(&project).expect("create project");
        let alias_project = fixture.alias_root.join("repo");

        let from_alias = normalize_project_path_with_policy(&alias_project, &fixture.policy())
            .expect("normalize alias project");
        let from_canonical = normalize_project_path_with_policy(&project, &fixture.policy())
            .expect("normalize canonical project");

        assert!(from_alias.used_alias_prefix());
        assert_eq!(from_alias.canonical_path(), from_canonical.canonical_path());
        assert!(
            from_alias
                .decision_trace()
                .iter()
                .any(|d| matches!(d, NormalizationDecision::AliasSymlinkVerified { .. }))
        );
    }

    #[test]
    fn reject_relative_path_input() {
        let fixture = TestFixture::new("relative", false, None);
        let err = normalize_project_path_with_policy(Path::new("relative/repo"), &fixture.policy())
            .expect_err("relative path must fail");
        assert_eq!(err.kind(), &PathNormalizationErrorKind::NotAbsoluteInput);
    }

    #[test]
    fn reject_path_outside_canonical_root() {
        let fixture = TestFixture::new("outside", false, None);
        let outside = fixture.root.join("outside");
        fs::create_dir_all(&outside).expect("create outside path");

        let err = normalize_project_path_with_policy(&outside, &fixture.policy())
            .expect_err("outside root must fail");
        log_normalization_error("reject_path_outside_canonical_root", &err);
        assert_eq!(
            err.kind(),
            &PathNormalizationErrorKind::OutsideCanonicalRoot
        );
        assert!(
            err.decision_trace()
                .iter()
                .any(|d| matches!(d, NormalizationDecision::CanonicalInputResolved(_)))
        );
    }

    #[cfg(unix)]
    #[test]
    fn reject_missing_alias_for_alias_prefixed_input() {
        let fixture = TestFixture::new("missing-alias", false, None);
        let input = fixture.alias_root.join("repo");
        let err = normalize_project_path_with_policy(&input, &fixture.policy())
            .expect_err("missing alias must fail");
        log_normalization_error("reject_missing_alias_for_alias_prefixed_input", &err);
        assert_eq!(err.kind(), &PathNormalizationErrorKind::AliasMissing);
    }

    #[cfg(unix)]
    #[test]
    fn reject_alias_pointing_to_wrong_target() {
        let fixture = TestFixture::new("wrong-target", false, None);
        let other_target = fixture.root.join("other-projects");
        fs::create_dir_all(&other_target).expect("create alternate target");
        symlink(&other_target, &fixture.alias_root).expect("create wrong alias");
        let alias_input = fixture.alias_root.join("repo");
        fs::create_dir_all(&alias_input).expect("create alias repo path");

        let err = normalize_project_path_with_policy(&alias_input, &fixture.policy())
            .expect_err("alias wrong target must fail");
        log_normalization_error("reject_alias_pointing_to_wrong_target", &err);
        assert_eq!(err.kind(), &PathNormalizationErrorKind::AliasWrongTarget);
    }

    #[cfg(unix)]
    #[test]
    fn reject_alias_path_that_is_not_symlink() {
        let fixture = TestFixture::new("alias-not-symlink", false, None);
        fs::create_dir_all(&fixture.alias_root).expect("create alias directory");
        let alias_input = fixture.alias_root.join("repo");
        fs::create_dir_all(&alias_input).expect("create alias repo path");

        let err = normalize_project_path_with_policy(&alias_input, &fixture.policy())
            .expect_err("non-symlink alias must fail");
        log_normalization_error("reject_alias_path_that_is_not_symlink", &err);
        assert_eq!(err.kind(), &PathNormalizationErrorKind::AliasNotSymlink);
        assert!(err.detail().contains("not a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn reject_alias_symlink_loop() {
        let fixture = TestFixture::new("alias-loop", false, None);
        symlink("dp", &fixture.alias_root).expect("create alias symlink loop");
        let alias_input = fixture.alias_root.join("repo");

        let err = normalize_project_path_with_policy(&alias_input, &fixture.policy())
            .expect_err("alias loop must fail");
        log_normalization_error("reject_alias_symlink_loop", &err);
        assert_eq!(
            err.kind(),
            &PathNormalizationErrorKind::AliasTargetResolveFailed
        );
        assert!(
            err.decision_trace()
                .iter()
                .any(|decision| matches!(decision, NormalizationDecision::AliasPrefixDetected(_)))
        );
    }

    #[cfg(unix)]
    #[test]
    fn reject_permission_denied_during_canonical_resolution() {
        let fixture = TestFixture::new("permission-denied", false, None);
        let project = fixture.canonical_root.join("repo");
        fs::create_dir_all(&project).expect("create project path");

        let original_permissions = fs::metadata(&fixture.canonical_root)
            .expect("read canonical root metadata")
            .permissions();
        let mut denied_permissions = original_permissions.clone();
        denied_permissions.set_mode(0o000);
        fs::set_permissions(&fixture.canonical_root, denied_permissions)
            .expect("lock canonical root permissions");

        let result = normalize_project_path_with_policy(&project, &fixture.policy());

        fs::set_permissions(&fixture.canonical_root, original_permissions)
            .expect("restore canonical root permissions");

        let err = match result {
            Ok(_) => {
                // Root users can bypass mode bits; treat as a non-actionable skip.
                return;
            }
            Err(err) => err,
        };
        log_normalization_error("reject_permission_denied_during_canonical_resolution", &err);
        assert!(matches!(
            err.kind(),
            PathNormalizationErrorKind::CanonicalRootResolveFailed
                | PathNormalizationErrorKind::InputResolveFailed
        ));
    }

    #[test]
    fn reject_when_canonical_root_missing() {
        let fixture = TestFixture::new("missing-root", false, None);
        let missing_root = fixture.root.join("does-not-exist");
        let policy = PathTopologyPolicy::new(missing_root.clone(), fixture.alias_root.clone());
        let outside = fixture.root.join("somewhere");
        fs::create_dir_all(&outside).expect("create input");

        let err = normalize_project_path_with_policy(&outside, &policy)
            .expect_err("missing canonical root must fail");
        log_normalization_error("reject_when_canonical_root_missing", &err);
        assert_eq!(
            err.kind(),
            &PathNormalizationErrorKind::CanonicalRootMissing
        );
        assert!(
            err.detail()
                .contains(missing_root.to_string_lossy().as_ref())
        );
    }
}
