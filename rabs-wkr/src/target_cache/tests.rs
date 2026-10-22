use super::*;
use crate::execution::{ExecutionTask, StopReason};
use crate::session::ExecResult;
use rabs_sandbox::canonical_namespace::Bind;
use rabs_sandbox::process_context::CommandContext;
use rabs_sandbox::source_transfer::SourceFile;
use rabs_sandbox::toolchain_dataset::ToolchainIdentity;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

fn inputs(root: &Path, names: &[&str]) -> WorkspaceInputs {
    let files = names
        .iter()
        .map(|name| {
            let bytes = fs::read(root.join(name)).unwrap();
            SourceFile {
                path: (*name).to_owned(),
                len: bytes.len() as u64,
                sha256: Sha256::digest(&bytes).into(),
                executable: false,
            }
        })
        .collect();
    let manifest = SourceManifest::new(files).unwrap();
    WorkspaceInputs {
        root: root.to_owned(),
        full_source_digest: manifest.digest(),
        manifest,
        projection: None,
        runtime_owner: None,
    }
}

fn runtime_inputs(root: &Path, names: &[&str]) -> WorkspaceInputs {
    inputs(root, names)
        .private_runtime_clone(&|| false)
        .unwrap()
}

fn fixture_request() -> CanonicalExecRequest {
    CanonicalExecRequest {
        request_id: 1,
        program: "/__rabs/toolchain/bin/cargo".to_owned(),
        args: vec![
            "build".to_owned(),
            "--frozen".to_owned(),
            "--offline".to_owned(),
        ],
        command_context: CommandContext::default(),
        dependency_context: None,
        toolchain_backing: "/private/toolchain".to_owned(),
        toolchain_identity: Some(ToolchainIdentity {
            sha256: [1; 32],
            files: 2,
            bytes: 3,
        }),
        workspace_backing: "/private/workspace".to_owned(),
        jobserver_grant: Some(1),
    }
}

fn fixture_spec(label: &str) -> CanonicalNamespaceSpec {
    let mut spec = CanonicalNamespaceSpec::new();
    spec.ro_binds
        .push(Bind::new("/private/source", "/__rabs/workspace"));
    spec.rw_binds
        .push(Bind::new("/private/target", "/__rabs/out/cargo"));
    spec.env = vec![
        ("CACHE_LABEL".to_owned(), label.to_owned()),
        ("CARGO_INCREMENTAL".to_owned(), "0".to_owned()),
        ("NUM_JOBS".to_owned(), "1".to_owned()),
    ];
    spec
}

fn support() -> HostIsolationSupport {
    // A pure key-construction fixture, not evidence of native namespace support.
    HostIsolationSupport {
        bubblewrap: Some("key-fixture".to_owned()),
        unprivileged_userns: true,
        overlayfs: false,
        cgroup_v2: false,
        landlock: false,
    }
}

fn scope() -> TargetCacheScope {
    TargetCacheScope::new(
        "worker",
        "coordinator:123",
        &ResultRecipient::TlsSpki([7; 32]),
    )
}

fn small_fixture() -> (
    tempfile::TempDir,
    ArtifactPlan,
    PreparedArtifacts,
    CapturedArtifacts,
) {
    let source = private_directory("rabs-hot-source-test-").unwrap();
    fs::write(source.path().join("lib.rs"), "pub fn answer() {}\n").unwrap();
    fs::set_permissions(
        source.path().join("lib.rs"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    let plan = ArtifactPlan::new_tree("cargo".to_owned(), vec!["artifact".to_owned()]).unwrap();
    let target = PreparedArtifacts::new(plan.clone()).unwrap();
    fs::write(target.backing().join("artifact"), "seed").unwrap();
    fs::create_dir(target.backing().join("empty-out-dir")).unwrap();
    fs::set_permissions(
        target.backing().join("empty-out-dir"),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    (source, plan, target, captured)
}

fn stage_small(
    cache: &Arc<TargetCache>,
    key: TargetKey,
) -> (PendingTargetSeed, ArtifactPlan, CapturedArtifacts) {
    let (source, plan, target, captured) = small_fixture();
    let (attempt, restored) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    let pending = attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap();
    (pending, plan, captured)
}

#[test]
fn target_key_binds_inputs_scope_toolchain_command_environment_and_grant() {
    let (source, plan, _, _) = small_fixture();
    let mut input = inputs(source.path(), &["lib.rs"]);
    let mut request = fixture_request();
    let mut spec = fixture_spec("first");
    let expected = target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap();
    spec.rw_binds[0].backing = "/different/private/clone".into();
    assert_eq!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 2).unwrap()
    );
    spec.env[0].1 = "second".to_owned();
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    spec.env[0].1 = "first".to_owned();
    spec.cwd = "/__rabs/workspace/member".into();
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    spec.cwd = "/__rabs/workspace".into();
    request.args.push("--release".into());
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    request.args.pop();
    request.toolchain_identity.as_mut().unwrap().sha256[0] ^= 1;
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    request.toolchain_identity.as_mut().unwrap().sha256[0] ^= 1;
    input.projection = Some((
        "isolated-registry-git-cargo-home-v1".into(),
        ".captured".into(),
    ));
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
    input.projection = None;
    for changed in [
        TargetCacheScope::new(
            "other-worker",
            "coordinator:123",
            &ResultRecipient::TlsSpki([7; 32]),
        ),
        TargetCacheScope::new(
            "worker",
            "other-coordinator:123",
            &ResultRecipient::TlsSpki([7; 32]),
        ),
        TargetCacheScope::new(
            "worker",
            "coordinator:123",
            &ResultRecipient::TlsSpki([8; 32]),
        ),
        TargetCacheScope::new(
            "worker",
            "coordinator:123",
            &ResultRecipient::LoopbackFixture,
        ),
    ] {
        assert_ne!(
            expected,
            target_key(changed, &request, &input, &spec, &support(), &plan, 1).unwrap()
        );
    }
    input.full_source_digest[0] ^= 1;
    assert_ne!(
        expected,
        target_key(scope(), &request, &input, &spec, &support(), &plan, 1).unwrap()
    );
}

#[test]
fn clones_preserve_bytes_timestamps_empty_directories_modes_and_private_link_groups() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, _) = small_fixture();
    fs::hard_link(
        target.backing().join("artifact"),
        target.backing().join("artifact-alias"),
    )
    .unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    let key = TargetKey([1; 32]);
    let original = fs::metadata(target.backing().join("artifact")).unwrap();
    let (attempt, restored) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let (_, restored) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    let restored = restored.unwrap();
    let cloned = fs::metadata(restored.backing().join("artifact")).unwrap();
    assert_ne!(original.ino(), cloned.ino());
    assert_eq!(
        cloned.ino(),
        fs::metadata(restored.backing().join("artifact-alias"))
            .unwrap()
            .ino()
    );
    assert_eq!(cloned.nlink(), 2);
    assert_eq!(original.modified().unwrap(), cloned.modified().unwrap());
    assert_eq!(
        fs::read(restored.backing().join("artifact")).unwrap(),
        b"seed"
    );
    assert_eq!(
        fs::metadata(restored.backing().join("empty-out-dir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    fs::write(restored.backing().join("artifact"), "mine").unwrap();
    assert_eq!(
        fs::read(restored.backing().join("artifact-alias")).unwrap(),
        b"mine"
    );
    let (_, independent) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    let independent = independent.unwrap();
    assert_eq!(
        fs::read(independent.backing().join("artifact")).unwrap(),
        b"seed"
    );
    assert_eq!(
        fs::read(independent.backing().join("artifact-alias")).unwrap(),
        b"seed"
    );
    assert_ne!(
        fs::metadata(independent.backing().join("artifact"))
            .unwrap()
            .ino(),
        cloned.ino()
    );
}

#[test]
fn external_hard_links_cannot_become_target_seeds() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let outside = private_directory("rabs-hot-external-link-").unwrap();
    fs::hard_link(
        target.backing().join("artifact"),
        outside.path().join("alias"),
    )
    .unwrap();
    let (attempt, _) = cache
        .acquire(
            TargetKey([1; 32]),
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(attempt.stage(&target, &captured, &|| false).is_err());
    let state = cache.state.lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.reserved_bytes, 0);
}

#[test]
fn unsafe_target_directory_modes_bypass_seeding_without_leaking_a_reservation() {
    for (name, mode, original, message) in [
        ("empty-out-dir", 0o555, 0o750, "owner-readable writable"),
        ("", 0o755, 0o700, "artifact tree root must be private"),
    ] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (source, plan, target, captured) = small_fixture();
        let directory = target.backing().join(name);
        fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
        let (attempt, _) = cache
            .acquire(
                TargetKey([1; 32]),
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                1,
                &|| false,
            )
            .unwrap();
        let error = attempt.stage(&target, &captured, &|| false).unwrap_err();
        assert!(error.to_string().contains(message), "{name:?}: {error}");
        let state = cache.state.lock().unwrap();
        assert!(state.entries.is_empty());
        assert_eq!(state.reserved_bytes, 0);
        // The fixture owns the original execution tree independently of the pool.
        fs::set_permissions(directory, fs::Permissions::from_mode(original)).unwrap();
    }
}

#[test]
fn corruption_refuses_the_seed_and_falls_back_to_a_fresh_target() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let key = TargetKey([2; 32]);
    let (attempt, _) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    attempt
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let path = cache.state.lock().unwrap().entries[0]
        .tree
        .directory
        .path()
        .join("artifact");
    fs::write(path, "evil").unwrap();
    let (_, restored) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            2,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    assert!(cache.state.lock().unwrap().entries.is_empty());
}

#[test]
fn pending_seeds_count_toward_both_bounds_and_drop_releases_reservations() {
    let cache = Arc::new(TargetCache::new(8).unwrap());
    let (first, _, _) = stage_small(&cache, TargetKey([1; 32]));
    let (second, _, _) = stage_small(&cache, TargetKey([2; 32]));
    assert!(cache.reserve(1).is_none());
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 8);
    drop(first);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 4);
    second.publish();
    assert_eq!(cache.state.lock().unwrap().retained_bytes, 4);
    let (third, _, _) = stage_small(&cache, TargetKey([3; 32]));
    third.publish();
    let (fourth, _, _) = stage_small(&cache, TargetKey([4; 32]));
    fourth.publish();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retained_bytes, 8);
    assert_eq!(state.entries.len(), 2);
    drop(state);
    let many = Arc::new(TargetCache::new(1024).unwrap());
    let reservations: Vec<_> = (0..MAX_TARGET_CACHE_ENTRIES)
        .map(|_| many.reserve(1).unwrap())
        .collect();
    assert!(many.reserve(1).is_none());
    drop(reservations);
    assert_eq!(many.state.lock().unwrap().reservations, 0);
}

#[test]
fn impossible_reservations_preserve_warm_bytes_and_lru_until_pending_copy_finishes() {
    let cache = Arc::new(TargetCache::new(12).unwrap());
    for tag in [1, 2] {
        stage_small(&cache, TargetKey([tag; 32])).0.publish();
    }
    let (pending, _, _) = stage_small(&cache, TargetKey([3; 32]));
    let paths: Vec<_> = cache
        .state
        .lock()
        .unwrap()
        .entries
        .iter()
        .map(|seed| seed.tree.directory.path().to_path_buf())
        .collect();
    // Four bytes are already owned by an unpublished copy. No eviction can
    // admit nine more under a twelve-byte limit. Repeated refusals must not
    // turn all subsequent builds cold or perturb the eviction order.
    for _ in 0..3 {
        assert!(cache.reserve(9).is_none());
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(state.reserved_bytes, 4);
        assert_eq!(state.reservations, 1);
        assert_eq!(
            state.entries.iter().map(|seed| seed.key).collect::<Vec<_>>(),
            vec![TargetKey([1; 32]), TargetKey([2; 32])]
        );
        for path in &paths {
            assert_eq!(fs::read(path.join("artifact")).unwrap(), b"seed");
        }
    }
    drop(pending);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    let (source, plan, _, _) = small_fixture();
    for tag in [1, 2] {
        let (_, restored) = cache
            .acquire(
                TargetKey([tag; 32]),
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                4,
                &|| false,
            )
            .unwrap();
        let restored = restored.expect("refused admission must leave the warm seed usable");
        assert_eq!(
            fs::read(restored.backing().join("artifact")).unwrap(),
            b"seed"
        );
    }
}

#[test]
fn staging_refusal_preserves_prior_seed_and_allows_later_publication() {
    let cache = Arc::new(TargetCache::new(12).unwrap());
    stage_small(&cache, TargetKey([1; 32])).0.publish();
    let held = cache.reserve(8).unwrap();
    let (source, plan, target, _) = small_fixture();
    fs::write(target.backing().join("artifact"), b"larger").unwrap();
    let captured = target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    let new_attempt = || {
        cache
            .acquire(
                TargetKey([2; 32]),
                runtime_inputs(source.path(), &["lib.rs"]),
                || PreparedArtifacts::new(plan.clone()),
                2,
                &|| false,
            )
            .unwrap()
            .0
    };
    assert!(
        new_attempt()
            .stage(&target, &captured, &|| false)
            .unwrap()
            .is_none()
    );
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].key, TargetKey([1; 32]));
        assert_eq!(state.retained_bytes, 4);
        assert_eq!(state.reserved_bytes, 8);
        assert_eq!(state.reservations, 1);
    }
    drop(held);
    new_attempt()
        .stage(&target, &captured, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.retained_bytes, 10);
    assert_eq!(state.entries.len(), 2);
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}

#[test]
fn feasible_reservations_keep_lru_eviction_exact_boundaries_and_entry_limits() {
    let cache = Arc::new(TargetCache::new(16).unwrap());
    for tag in [1, 2, 3] {
        stage_small(&cache, TargetKey([tag; 32])).0.publish();
    }
    let held = cache.reserve(4).unwrap();
    let next = cache.reserve(4).unwrap();
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(state.reserved_bytes, 8);
        assert_eq!(state.reservations, 2);
        assert_eq!(
            state.entries.iter().map(|seed| seed.key).collect::<Vec<_>>(),
            vec![TargetKey([2; 32]), TargetKey([3; 32])]
        );
    }
    // Exact remaining capacity is admissible, not a false >= refusal.
    let boundary = cache.reserve(8).unwrap();
    assert!(cache.state.lock().unwrap().entries.is_empty());
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 16);
    assert!(cache.reserve(1).is_none());
    drop((boundary, next, held));
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    assert_eq!(cache.state.lock().unwrap().reservations, 0);

    stage_small(&cache, TargetKey([4; 32])).0.publish();
    let mut empty: Vec<_> = (0..MAX_TARGET_CACHE_ENTRIES - 1)
        .map(|_| cache.reserve(0).unwrap())
        .collect();
    assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    empty.push(cache.reserve(0).unwrap());
    assert!(cache.state.lock().unwrap().entries.is_empty());
    assert!(cache.reserve(0).is_none());
    drop(empty);
    assert_eq!(cache.state.lock().unwrap().reservations, 0);
}

#[test]
fn failed_output_allocation_does_not_evict_or_promote_a_valid_seed() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    for tag in [1, 2] {
        stage_small(&cache, TargetKey([tag; 32])).0.publish();
    }
    let (source, plan, _, _) = small_fixture();
    let (_, restored) = cache
        .acquire(
            TargetKey([1; 32]),
            runtime_inputs(source.path(), &["lib.rs"]),
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected destination allocation failure",
                ))
            },
            3,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.retained_bytes, 8);
        assert_eq!(
            state.entries.iter().map(|seed| seed.key).collect::<Vec<_>>(),
            vec![TargetKey([1; 32]), TargetKey([2; 32])]
        );
    }
    let (_, restored) = cache
        .acquire(
            TargetKey([1; 32]),
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            4,
            &|| false,
        )
        .unwrap();
    assert_eq!(
        fs::read(restored.unwrap().backing().join("artifact")).unwrap(),
        b"seed"
    );
}

#[test]
fn cancelled_restore_preserves_seed_but_never_bypasses_later_verification() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([1; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, _, _) = small_fixture();
    let stopped = std::cell::Cell::new(false);
    let error = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || {
                let output = PreparedArtifacts::new(plan.clone())?;
                stopped.set(true);
                Ok(output)
            },
            2,
            &|| stopped.get(),
        )
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    ));
    let path = {
        let state = cache.state.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.retained_bytes, 4);
        state.entries[0].tree.directory.path().join("artifact")
    };
    assert_eq!(fs::read(&path).unwrap(), b"seed");
    // Retention is not trust. A corrupt retained seed must still be refused
    // and evicted by the unchanged verification on the next attempted hit.
    fs::write(path, b"evil").unwrap();
    let (_, restored) = cache
        .acquire(
            key,
            runtime_inputs(source.path(), &["lib.rs"]),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    let state = cache.state.lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.retained_bytes, 0);
    assert_eq!(state.reserved_bytes, 0);
}

struct ThreadWake(std::thread::Thread);
impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

#[test]
fn only_frozen_success_can_publish_a_pending_seed() {
    for outcome in [
        "success",
        "cancel",
        "failure",
        "residual",
        "missing-artifacts",
        "bad-diagnostics",
    ] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (seed, plan, captured) = stage_small(&cache, TargetKey([1; 32]));
        let mut task =
            ExecutionTask::spawn_with_artifacts(1, Duration::from_secs(10), plan, move |control| {
                control.retain_target_seed(seed).unwrap();
                if outcome != "missing-artifacts" {
                    control.retain_artifacts(Ok(captured)).unwrap();
                }
                if outcome == "cancel" {
                    control.cancel(StopReason::Cancelled);
                }
                if outcome == "bad-diagnostics" {
                    control
                        .retain_outputs(Err("fixture capture failure".to_owned()))
                        .unwrap();
                }
                ExecResult {
                    request_id: 1,
                    exit_code: if outcome == "failure" { 1 } else { 0 },
                    stdout_sha256: crate::session::sha256_hex(b""),
                    stderr_sha256: crate::session::sha256_hex(b""),
                    executed: true,
                    residual_group_members: u32::from(outcome == "residual"),
                    stdout_spill_bytes: 0,
                    stderr_spill_bytes: 0,
                    stdout_spill_path: None,
                    stderr_spill_path: None,
                }
            })
            .unwrap();
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match task.poll_completion(&mut context) {
                Poll::Ready(result) => {
                    assert_eq!(
                        result.is_ok(),
                        matches!(outcome, "success" | "cancel" | "failure"),
                        "{outcome}"
                    );
                    break;
                }
                Poll::Pending => {
                    assert!(Instant::now() < deadline);
                    std::thread::park_timeout(Duration::from_millis(20));
                }
            }
        }
        drop(task);
        let state = cache.state.lock().unwrap();
        assert_eq!(
            state.entries.len(),
            usize::from(outcome == "success"),
            "{outcome}"
        );
        assert_eq!(state.reserved_bytes, 0, "{outcome}");
        assert_eq!(state.reservations, 0, "{outcome}");
    }
}

const BUILD_SCRIPT: &str = r#"fn main() {
    let root = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let count = std::fs::read_to_string(root.join("run-count")).ok().map(|text| text.parse::<u32>().unwrap()).unwrap_or(0) + 1;
    std::fs::write(root.join("run-count"), count.to_string()).unwrap();
    std::fs::create_dir_all(root.join("empty")).unwrap();
    let value = std::fs::read_to_string("input.txt").unwrap().trim().parse::<u32>().unwrap() + OFFSET;
    std::fs::write(root.join("answer.rs"), value.to_string()).unwrap();
    println!("cargo:rustc-env=LABEL={}", std::env::var("CACHE_LABEL").unwrap());
    println!("cargo:rerun-if-changed=input.txt");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CACHE_LABEL");
}
"#;

struct CargoFixture {
    root: tempfile::TempDir,
    workspace: PathBuf,
    plan: ArtifactPlan,
}

impl CargoFixture {
    fn new() -> Self {
        let root = private_directory("rabs-real-hot-cargo-").unwrap();
        let workspace = root.path().join("source");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(workspace.join("src")).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            "[package]\nname='hot_fixture'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        fs::write(
            workspace.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = 'hot_fixture'\nversion = '0.1.0'\n",
        )
        .unwrap();
        fs::write(workspace.join("src/main.rs"), "fn main() { println!(\"{}:{}\", env!(\"LABEL\"), include!(concat!(env!(\"OUT_DIR\"), \"/answer.rs\"))); }\n").unwrap();
        fs::write(
            workspace.join("build.rs"),
            BUILD_SCRIPT.replace("OFFSET", "0"),
        )
        .unwrap();
        fs::write(workspace.join("input.txt"), "40\n").unwrap();
        let plan = ArtifactPlan::new_tree("cargo".to_owned(), vec!["debug/hot_fixture".to_owned()])
            .unwrap();
        Self {
            root,
            workspace,
            plan,
        }
    }

    fn input(&self) -> WorkspaceInputs {
        inputs(
            &self.workspace,
            &[
                "Cargo.toml",
                "Cargo.lock",
                "build.rs",
                "input.txt",
                "src/main.rs",
            ],
        )
    }

    fn fresh_upload_timestamps(&self) {
        // Model a new private SourceReceiver materialization of identical bytes.
        // Use actual wall time, never artificial future output timestamps.
        for file in self.input().manifest.files() {
            File::open(self.workspace.join(&file.path))
                .unwrap()
                .set_times(FileTimes::new().set_modified(SystemTime::now()))
                .unwrap();
        }
        for directory in [&self.workspace, &self.workspace.join("src")] {
            File::open(directory)
                .unwrap()
                .set_times(FileTimes::new().set_modified(SystemTime::now()))
                .unwrap();
        }
    }

    fn build(&self, cache: &Arc<TargetCache>, label: &str, hit: bool, expected: &str) {
        let sealed_times = SourceTimes::capture(&self.input(), &|| false).unwrap();
        let runtime_directory = tempfile::Builder::new()
            .prefix("workspace")
            .rand_bytes(0)
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(self.root.path())
            .unwrap();
        let input = self
            .input()
            .clone_into(runtime_directory, &|| false)
            .unwrap();
        let workspace = input.root.clone();
        let key = target_key(
            scope(),
            &fixture_request(),
            &input,
            &fixture_spec(label),
            &support(),
            &self.plan,
            1,
        )
        .unwrap();
        let (attempt, restored) = cache
            .acquire(
                key,
                input,
                || PreparedArtifacts::fixture(self.plan.clone(), self.root.path()),
                1,
                &|| false,
            )
            .unwrap();
        assert_eq!(
            restored.is_some(),
            hit,
            "unexpected target seed disposition"
        );
        let target = restored.unwrap_or_else(|| {
            PreparedArtifacts::fixture(self.plan.clone(), self.root.path()).unwrap()
        });
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args([
                "build",
                "--frozen",
                "--offline",
                "--message-format=json",
                "--jobs=1",
            ])
            .arg("--manifest-path")
            .arg(workspace.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(target.backing())
            .current_dir(&workspace)
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env("RUSTFLAGS", "-C debuginfo=0")
            .env("CARGO_INCREMENTAL", "0")
            .env("CACHE_LABEL", label)
            .output()
            .expect("run the real installed Cargo");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let fresh: Vec<_> = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .map(|message| message["fresh"].as_bool().unwrap())
            .collect();
        assert!(
            fresh.len() >= 2,
            "both build script and executable must be observed"
        );
        assert!(
            fresh.iter().all(|value| *value == hit),
            "Cargo freshness {fresh:?}, expected hit={hit}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let binary = Command::new(target.backing().join("debug/hot_fixture"))
            .output()
            .unwrap();
        assert!(binary.status.success());
        assert_eq!(String::from_utf8(binary.stdout).unwrap().trim(), expected);
        let captured = target
            .capture_with_dependency_inputs(None, || false)
            .unwrap();
        let counts: Vec<_> = captured
            .file_names()
            .filter(|name| name.ends_with("/out/run-count"))
            .collect();
        assert_eq!(counts.len(), 1);
        assert_eq!(
            fs::read_to_string(target.backing().join(counts[0])).unwrap(),
            "1",
            "a fresh build script must not rerun after seeding"
        );
        assert!(
            captured
                .file_names()
                .any(|name| name.ends_with("/out/answer.rs"))
        );
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .unwrap()
            .publish();
        assert_eq!(
            SourceTimes::capture(&self.input(), &|| false).unwrap(),
            sealed_times,
            "the original sealed source's metadata must remain unchanged"
        );
        // Dropping this owner removes the execution target. The next run can
        // obtain its target bytes only from an independently verified seed.
    }
}

#[test]
fn real_cargo_private_seed_is_fresh_and_source_build_script_environment_changes_miss() {
    let fixture = CargoFixture::new();
    let cache = Arc::new(TargetCache::new(128 * 1024 * 1024).unwrap());
    fixture.build(&cache, "first", false, "first:40");
    fixture.fresh_upload_timestamps();
    fixture.build(&cache, "first", true, "first:40");
    fs::write(fixture.workspace.join("input.txt"), "41\n").unwrap();
    fixture.build(&cache, "first", false, "first:41");
    fs::write(
        fixture.workspace.join("build.rs"),
        BUILD_SCRIPT.replace("OFFSET", "1"),
    )
    .unwrap();
    fixture.build(&cache, "first", false, "first:42");
    fixture.build(&cache, "second", false, "second:42");
    fixture.fresh_upload_timestamps();
    fixture.build(&cache, "second", true, "second:42");
}

#[test]
fn cold_and_contended_attempts_do_not_copy_the_sealed_workspace() {
    for contended in [false, true] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let (source, plan, target, captured) = small_fixture();
        let original = inputs(source.path(), &["lib.rs"]);
        let before = SourceTimes::capture(&original, &|| false).unwrap();
        let calls = std::cell::Cell::new(0);
        let held = contended.then(|| cache.state.lock().unwrap());
        let (attempt, restored) = cache
            .acquire(
                TargetKey([31; 32]),
                original.clone(),
                || {
                    calls.set(calls.get() + 1);
                    PreparedArtifacts::new(plan.clone())
                },
                1,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        assert_eq!(calls.get(), 0, "cold acquisition must not allocate a target copy");
        assert_eq!(attempt.inputs.root, source.path());
        assert!(attempt.inputs.runtime_owner.is_none());
        assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
        drop(held);
        // Read-only input observation still supports successful cold capture.
        attempt
            .stage(&target, &captured, &|| false)
            .unwrap()
            .unwrap()
            .publish();
        assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
        assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    }
}

#[test]
fn a_warm_hit_lazily_owns_its_source_and_preserves_the_original_seal() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let key = TargetKey([32; 32]);
    let first_time = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    File::open(source.path().join("lib.rs"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(first_time))
        .unwrap();
    let retained_times = SourceTimes::capture(&original, &|| false).unwrap();
    let (cold, restored) = cache
        .acquire(key, original.clone(), || PreparedArtifacts::new(plan.clone()), 1, &|| false)
        .unwrap();
    assert!(restored.is_none());
    assert!(cold.inputs.runtime_owner.is_none());
    cold.stage(&target, &captured, &|| false).unwrap().unwrap().publish();

    // A later upload of the same bytes has different source timestamps. Only
    // the independently owned runtime tree may receive the retained times.
    File::open(source.path().join("lib.rs"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(first_time + Duration::from_secs(10)))
        .unwrap();
    let before = SourceTimes::capture(&original, &|| false).unwrap();
    assert_ne!(before, retained_times);
    let (warm, restored) = cache
        .acquire(key, original.clone(), || PreparedArtifacts::new(plan.clone()), 2, &|| false)
        .unwrap();
    let restored = restored.expect("the exact seed must remain reusable");
    assert_ne!(warm.inputs.root, original.root);
    assert_eq!(warm.inputs.runtime_owner.as_ref().unwrap().path(), warm.inputs.root);
    assert_eq!(SourceTimes::capture(&warm.inputs, &|| false).unwrap(), retained_times);
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    let source_inode = fs::metadata(source.path().join("lib.rs")).unwrap();
    let runtime_inode = fs::metadata(warm.inputs.root.join("lib.rs")).unwrap();
    assert_ne!(
        (source_inode.dev(), source_inode.ino()),
        (runtime_inode.dev(), runtime_inode.ino())
    );
    assert_eq!(fs::read(restored.backing().join("artifact")).unwrap(), b"seed");
    let runtime_path = warm.inputs.root.clone();
    drop(warm);
    assert!(!runtime_path.exists(), "the attempt must own the complete copy lifetime");
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    // The timestamp-restoration guard itself remains unchanged.
    assert!(retained_times.restore(&original, &|| false).is_err());
}

#[test]
fn refused_lazy_restore_keeps_the_original_workspace_and_fresh_target_path() {
    for corrupt in [false, true] {
        let cache = Arc::new(TargetCache::new(1024).unwrap());
        let key = TargetKey([33; 32]);
        stage_small(&cache, key).0.publish();
        if corrupt {
            let path = cache.state.lock().unwrap().entries[0]
                .tree.directory.path().join("artifact");
            fs::write(path, b"evil").unwrap();
        }
        let (source, plan, _, _) = small_fixture();
        let original = inputs(source.path(), &["lib.rs"]);
        let before = SourceTimes::capture(&original, &|| false).unwrap();
        let (attempt, restored) = cache
            .acquire(
                key,
                original.clone(),
                || {
                    if corrupt {
                        PreparedArtifacts::new(plan.clone())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "injected allocation refusal",
                        ))
                    }
                },
                2,
                &|| false,
            )
            .unwrap();
        assert!(restored.is_none());
        assert_eq!(attempt.inputs.root, original.root);
        assert!(attempt.inputs.runtime_owner.is_none());
        assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
        assert_eq!(cache.state.lock().unwrap().entries.len(), usize::from(!corrupt));
    }
}

#[test]
fn cancellation_before_lazy_source_copy_keeps_seed_and_drops_the_new_target() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([34; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, _, _) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let before = SourceTimes::capture(&original, &|| false).unwrap();
    let stopped = std::cell::Cell::new(false);
    let new_output_path = std::cell::RefCell::new(None);
    let error = cache
        .acquire(
            key,
            original.clone(),
            || {
                let output = PreparedArtifacts::new(plan.clone())?;
                *new_output_path.borrow_mut() = Some(output.backing().to_path_buf());
                stopped.set(true);
                Ok(output)
            },
            2,
            &|| stopped.get(),
        )
        .unwrap_err();
    assert!(matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::TimedOut));
    assert!(!new_output_path.borrow().as_ref().unwrap().exists());
    assert_eq!(cache.state.lock().unwrap().entries.len(), 1);
    assert_eq!(cache.state.lock().unwrap().reserved_bytes, 0);
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
}

#[test]
fn a_cold_attempt_still_refuses_changed_sealed_source_before_seed_publication() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, target, captured) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let (attempt, restored) = cache
        .acquire(
            TargetKey([35; 32]),
            original,
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap();
    assert!(restored.is_none());
    assert!(attempt.inputs.runtime_owner.is_none());
    fs::set_permissions(source.path().join("lib.rs"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(source.path().join("lib.rs"), b"changed source").unwrap();
    assert!(attempt.stage(&target, &captured, &|| false).is_err());
    let state = cache.state.lock().unwrap();
    assert!(state.entries.is_empty());
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}

#[test]
fn lazy_restoration_binds_both_owned_mounts_or_changes_neither() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([36; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, current, _) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let (attempt, restored) = cache
        .acquire(key, original.clone(), || PreparedArtifacts::new(plan.clone()), 2, &|| false)
        .unwrap();
    let restored = restored.unwrap();
    let make_spec = || {
        let mut spec = fixture_spec("unchanged");
        spec.ro_binds[0].backing = original.root.clone();
        spec.rw_binds[0].backing = current.backing().to_path_buf();
        spec
    };
    let request = fixture_request();
    let mut spec = make_spec();
    let expected_key =
        target_key(scope(), &request, &original, &spec, &support(), &plan, 1).unwrap();
    attempt.bind_restored(&mut spec, &original, &current, &restored, &plan).unwrap();
    assert_eq!(spec.ro_binds[0].backing, attempt.inputs.root);
    assert_eq!(spec.rw_binds[0].backing, restored.backing());
    assert_eq!(
        target_key(scope(), &request, &attempt.inputs, &spec, &support(), &plan, 1).unwrap(),
        expected_key,
        "private backing selection must not change the exact semantic key"
    );
    for wrong_source in [false, true] {
        let mut spec = make_spec();
        if wrong_source {
            spec.ro_binds[0].backing = "/unowned/source".into();
        } else {
            spec.rw_binds[0].backing = "/unowned/target".into();
        }
        let before_source = spec.ro_binds[0].backing.clone();
        let before_output = spec.rw_binds[0].backing.clone();
        assert!(attempt.bind_restored(&mut spec, &original, &current, &restored, &plan).is_err());
        assert_eq!(spec.ro_binds[0].backing, before_source);
        assert_eq!(spec.rw_binds[0].backing, before_output);
    }
    let mut changed = original.clone();
    changed.full_source_digest[0] ^= 1;
    let mut spec = make_spec();
    assert!(attempt.bind_restored(&mut spec, &changed, &current, &restored, &plan).is_err());
    assert_eq!(spec.ro_binds[0].backing, original.root);
    assert_eq!(spec.rw_binds[0].backing, current.backing());
    let (cold, _) = cache
        .acquire(
            TargetKey([37; 32]),
            original.clone(),
            || PreparedArtifacts::new(plan.clone()),
            3,
            &|| false,
        )
        .unwrap();
    let mut spec = make_spec();
    assert!(cold.bind_restored(&mut spec, &original, &current, &restored, &plan).is_err());
    assert_eq!(spec.ro_binds[0].backing, original.root);
    assert_eq!(spec.rw_binds[0].backing, current.backing());
}

#[test]
fn a_mismatched_runtime_owner_is_not_treated_as_a_sealed_source() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let (source, plan, _, _) = small_fixture();
    let mut original = inputs(source.path(), &["lib.rs"]);
    original.runtime_owner = Some(Arc::new(
        private_directory("rabs-wrong-runtime-owner-").unwrap(),
    ));
    let error = cache
        .acquire(
            TargetKey([38; 32]),
            original,
            || PreparedArtifacts::new(plan.clone()),
            1,
            &|| false,
        )
        .unwrap_err();
    assert!(error.to_string().contains("runtime owner differs"));
    assert!(cache.state.lock().unwrap().entries.is_empty());
}

#[test]
fn live_warm_attempts_own_independent_source_inodes_and_publication_checks() {
    let cache = Arc::new(TargetCache::new(1024).unwrap());
    let key = TargetKey([39; 32]);
    stage_small(&cache, key).0.publish();
    let (source, plan, _, _) = small_fixture();
    let original = inputs(source.path(), &["lib.rs"]);
    let before = SourceTimes::capture(&original, &|| false).unwrap();
    let acquire = || {
        let (attempt, restored) = cache
            .acquire(
                key,
                original.clone(),
                || PreparedArtifacts::new(plan.clone()),
                2,
                &|| false,
            )
            .unwrap();
        (attempt, restored.expect("matching seed must be restored"))
    };
    // Both attempts stay live together. Neither source nor target may alias
    // the other attempt, the retained seed, or the original sealed workspace.
    let (first, first_target) = acquire();
    let (second, second_target) = acquire();
    let identity = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    };
    let first_source = first.inputs.root.join("lib.rs");
    let second_source = second.inputs.root.join("lib.rs");
    assert_ne!(identity(&first_source), identity(&second_source));
    assert_ne!(identity(&first_source), identity(&original.root.join("lib.rs")));
    assert_ne!(identity(&second_source), identity(&original.root.join("lib.rs")));
    assert_ne!(
        identity(&first_target.backing().join("artifact")),
        identity(&second_target.backing().join("artifact"))
    );
    let original_bytes = fs::read(&second_source).unwrap();
    fs::set_permissions(&first_source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&first_source, b"changed private workspace").unwrap();
    assert_eq!(fs::read(&second_source).unwrap(), original_bytes);
    assert_eq!(fs::read(original.root.join("lib.rs")).unwrap(), original_bytes);
    assert_eq!(SourceTimes::capture(&original, &|| false).unwrap(), before);
    let first_capture = first_target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    assert!(first.stage(&first_target, &first_capture, &|| false).is_err());
    let second_capture = second_target
        .capture_with_dependency_inputs(None, || false)
        .unwrap();
    second
        .stage(&second_target, &second_capture, &|| false)
        .unwrap()
        .unwrap()
        .publish();
    let state = cache.state.lock().unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.reserved_bytes, 0);
    assert_eq!(state.reservations, 0);
}
