//! Exercise live selector policy without SSH, package installs or host config.
use super::*;
use rch_common::WorkerConfig;

async fn versioned_pool() -> WorkerPool {
    let pool = WorkerPool::new();
    for (id, priority) in [("matching", 1), ("incompatible", 1000)] {
        pool.add_worker(WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_owned(),
            user: "fixture".to_owned(),
            identity_file: "unused-test-key".to_owned(),
            total_slots: 8,
            priority,
            tags: Vec::new(),
            tools: Vec::new(),
        })
        .await;
        pool.set_status(&WorkerId::new(id), WorkerStatus::Healthy)
            .await;
    }
    for worker in pool.all_workers().await {
        let matches = worker.config.read().await.id.as_str() == "matching";
        worker.set_speed_score(if matches { 1.0 } else { 99.0 });
        worker
            .set_capabilities(WorkerCapabilities {
                node_version: Some(if matches { "v26.7.0" } else { "v22.0.0" }.to_owned()),
                bun_version: Some(if matches { "1.3.0" } else { "1.2.9" }.to_owned()),
                num_cpus: Some(8),
                disk_free_gb: Some(100.0),
                disk_total_gb: Some(200.0),
                projects_root_ok: Some(true),
                tools_present: vec!["clang".to_owned()],
                ..Default::default()
            })
            .await;
    }
    pool
}

fn request(runtime: RequiredRuntime, requirement: &str) -> SelectionRequest {
    SelectionRequest {
        job_mode: true,
        project: "exact-runtime-fixture".to_owned(),
        command: Some(match runtime {
            RequiredRuntime::Bun => "bun test".to_owned(),
            _ => "node script.js".to_owned(),
        }),
        command_priority: CommandPriority::Normal,
        estimated_cores: 1,
        disk_headroom_gib: 0,
        preferred_workers: Vec::new(),
        toolchain: None,
        required_runtime: runtime,
        classification_duration_us: None,
        hook_pid: None,
        required_tools: vec![requirement.to_owned(), "clang".to_owned()],
    }
}

#[tokio::test]
async fn exact_version_eligibility_precedes_all_five_ranking_strategies() {
    for (runtime, requirement) in [
        (RequiredRuntime::Node, "node@26.7.0"),
        (RequiredRuntime::Bun, "bun@1.3.0"),
    ] {
        for strategy in [
            SelectionStrategy::Priority,
            SelectionStrategy::Fastest,
            SelectionStrategy::Balanced,
            SelectionStrategy::CacheAffinity,
            SelectionStrategy::FairFastest,
        ] {
            let pool = versioned_pool().await;
            let selector = WorkerSelector::with_config(
                SelectionConfig {
                    strategy,
                    ..Default::default()
                },
                CircuitBreakerConfig::default(),
            );
            let outcome = selector.select(&pool, &request(runtime, requirement)).await;
            let worker = outcome
                .worker
                .expect("matching reported runtime must remain usable");
            assert_eq!(worker.config.read().await.id.as_str(), "matching");
        }
    }
}

#[tokio::test]
async fn explicit_worker_preferences_do_not_override_exact_runtime_constraints() {
    let pool = versioned_pool().await;
    let selector =
        WorkerSelector::with_config(SelectionConfig::default(), CircuitBreakerConfig::default());
    let mut request = request(RequiredRuntime::Node, "node@26.7.0");
    request.preferred_workers = vec![WorkerId::new("incompatible")];
    assert!(selector.select(&pool, &request).await.worker.is_none());
}

#[tokio::test]
async fn conflicting_or_unsupported_constraints_cannot_fall_back_to_another_worker() {
    for constraints in [
        vec!["node@26.7.0", "node@22.0.0"],
        vec!["node@26.7.0", "rust@1.90.0"],
        vec!["node@26.7.0", "bun@1.2.9"],
    ] {
        let pool = versioned_pool().await;
        let selector = WorkerSelector::with_config(
            SelectionConfig::default(),
            CircuitBreakerConfig::default(),
        );
        let mut request = request(RequiredRuntime::Node, "node@26.7.0");
        request.required_tools = constraints.into_iter().map(str::to_owned).collect();
        assert!(selector.select(&pool, &request).await.worker.is_none());
    }
}

#[test]
fn malformed_or_missing_runtime_facts_cannot_be_replaced_by_named_labels() {
    let request = request(RequiredRuntime::Node, "node@26.7.0");
    for version in [
        None,
        Some("v22.0.0"),
        Some("v26.7"),
        Some("v26.7.0\nforged"),
    ] {
        let capabilities = WorkerCapabilities {
            node_version: version.map(str::to_owned),
            tools_present: vec!["node@26.7.0".to_owned(), "clang".to_owned()],
            ..Default::default()
        };
        let reason = required_tool_capability_mismatch(&request, &capabilities).unwrap();
        assert!(
            reason.starts_with("capability_missing:runtime_version:node:"),
            "{reason}"
        );
        assert!(!reason.chars().any(char::is_control));
    }
}

#[tokio::test]
async fn last_success_affinity_cannot_bypass_required_runtime_or_named_tools() {
    let pool = versioned_pool().await;
    let mut config = SelectionConfig::default();
    config.affinity.enable_last_success_fallback = true;
    let selector = WorkerSelector::with_config(config, CircuitBreakerConfig::default());
    let mut request = request(RequiredRuntime::Node, "node@26.7.0");
    request.job_mode = false;
    selector
        .cache_tracker
        .write()
        .await
        .record_success("incompatible", &request.project);
    let excluded = HashSet::new();

    let requirements = std::mem::take(&mut request.required_tools);
    assert_eq!(
        selector
            .try_fallback(&pool, &request, &excluded)
            .await
            .as_deref(),
        Some("incompatible")
    );
    request.required_tools = requirements;
    assert!(
        selector
            .try_fallback(&pool, &request, &excluded)
            .await
            .is_none()
    );

    let worker = pool.get(&WorkerId::new("incompatible")).await.unwrap();
    let mut capabilities = worker.capabilities().await;
    capabilities.node_version = Some("v26.7.0".to_owned());
    worker.set_capabilities(capabilities.clone()).await;
    assert_eq!(
        selector
            .try_fallback(&pool, &request, &excluded)
            .await
            .as_deref(),
        Some("incompatible")
    );
    capabilities.tools_present.clear();
    worker.set_capabilities(capabilities).await;
    assert!(
        selector
            .try_fallback(&pool, &request, &excluded)
            .await
            .is_none()
    );
}
