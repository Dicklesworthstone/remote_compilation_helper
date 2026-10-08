//! Recover the default daemon across service/shell runtime-directory contexts.
//!
//! Explicit socket configuration is an authority boundary, not a hint. Only
//! default-derived sockets may discover another endpoint. Discovered peers
//! must belong to our effective UID, and an unhealthy live listener must not
//! be replaced by a second daemon with independent worker-slot accounting.

use super::*;
use rch_common::ConfigValueSource;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};

#[derive(Debug, PartialEq, Eq)]
enum Probe {
    Absent,
    Healthy,
    Busy,
}

#[derive(Debug, PartialEq, Eq)]
enum Discovery {
    Absent,
    Healthy(PathBuf),
    Busy,
}

fn source_allows_discovery(source: Option<&ConfigValueSource>) -> bool {
    matches!(source, Some(ConfigValueSource::Default))
}

/// Obtain our effective UID without an external command or unsafe code. The
/// kernel reports the credentials of this process on its own socket pair.
fn effective_uid() -> io::Result<u32> {
    let (socket, _peer) = UnixStream::pair()?;
    Ok(socket.peer_cred()?.uid())
}

fn candidates_for_context(
    requested: &Path,
    runtime_dir: Option<&Path>,
    cache_dir: Option<&Path>,
    uid: u32,
    linux_runtime: bool,
) -> Vec<PathBuf> {
    let mut candidates = vec![requested.to_path_buf()];
    let mut add = |path: PathBuf| {
        if path.is_absolute() && !candidates.contains(&path) {
            candidates.push(path);
        }
    };
    if let Some(runtime_dir) = runtime_dir {
        add(runtime_dir.join("rch.sock"));
    }
    if let Some(cache_dir) = cache_dir {
        add(cache_dir.join("rch/rch.sock"));
    }
    // A system service may have no XDG_RUNTIME_DIR even though a login
    // session for the same UID already started the default daemon there.
    if linux_runtime {
        add(PathBuf::from(format!("/run/user/{uid}/rch.sock")));
    }
    add(PathBuf::from("/tmp/rch.sock"));
    candidates
}

/// Unlike XDG_RUNTIME_DIR and TMPDIR, this namespace is shared by service and
/// login contexts on one host. Never repair, chmod or follow an unsafe entry.
fn prepare_state_dir(path: &Path, uid: u32) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon discovery state must be a private directory owned by the effective UID",
        ));
    }
    Ok(())
}

/// Remember a verified endpoint so clients with disjoint environment-derived
/// candidate lists can still find the daemon chosen by another starter. This
/// is a discovery hint, never readiness evidence: every use probes the peer.
const ENDPOINT_RECORD_LIMIT: u64 = 4096;

fn candidates_with_record(
    candidates: &[PathBuf],
    state_dir: &Path,
    uid: u32,
) -> io::Result<Vec<PathBuf>> {
    let record = state_dir.join("endpoint");
    let metadata = match std::fs::symlink_metadata(&record) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidates.to_vec()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > ENDPOINT_RECORD_LIMIT
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe daemon endpoint discovery record",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(record)?
        .take(ENDPOINT_RECORD_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    let endpoint = parse_endpoint_record(&bytes)?;
    let mut result = vec![endpoint];
    for candidate in candidates {
        if !result.contains(candidate) {
            result.push(candidate.clone());
        }
    }
    Ok(result)
}

fn parse_endpoint_record(bytes: &[u8]) -> io::Result<PathBuf> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let path = PathBuf::from(text);
    // The effective RCH socket setting is a String. Refuse unrepresentable
    // endpoints rather than health-checking one path then dispatching to a
    // lossy UTF-8 replacement of it.
    if bytes.len() as u64 > ENDPOINT_RECORD_LIMIT || bytes.contains(&0) || !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon endpoint record must contain one absolute UTF-8 path",
        ));
    }
    Ok(path)
}

fn remember_endpoint(state_dir: &Path, endpoint: &Path) -> io::Result<()> {
    let bytes = endpoint.as_os_str().as_encoded_bytes();
    parse_endpoint_record(bytes)?;
    // Called with the discovery gate held. Atomic replacement means readers
    // see the old complete hint or the new complete hint, never a partial path.
    let mut temporary = tempfile::NamedTempFile::new_in(state_dir)?;
    std::io::Write::write_all(&mut temporary, bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(state_dir.join("endpoint"))
        .map_err(|error| error.error)?;
    Ok(())
}

async fn probe_candidate(path: &Path, uid: u32) -> Probe {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == uid => {}
        Ok(_) => return Probe::Absent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Probe::Absent,
        Err(_) => return Probe::Busy,
    }
    if path.to_str().is_none() {
        // RCH's socket configuration cannot represent this endpoint. Keep a
        // same-user socket conservative rather than silently changing bytes.
        return Probe::Busy;
    }
    let budget = Duration::from_millis(300);
    let exchange = async {
        let stream = match UnixStream::connect(path).await {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Probe::Absent;
            }
            Err(_) => return Probe::Busy,
        };
        match stream.peer_cred() {
            Ok(credentials) if credentials.uid() == uid => {}
            Ok(_) => return Probe::Absent,
            Err(_) => return Probe::Busy,
        }
        let (reader, mut writer) = stream.into_split();
        if writer.write_all(b"GET /health\n").await.is_err() || writer.flush().await.is_err() {
            return Probe::Busy;
        }
        let Ok(body) = daemon_ipc::read_daemon_body(reader, budget, false).await else {
            return Probe::Busy;
        };
        match serde_json::from_str::<HealthResponse>(&body) {
            Ok(response) if response.status == "healthy" => Probe::Healthy,
            _ => Probe::Busy,
        }
    };
    timeout(budget, exchange).await.unwrap_or(Probe::Busy)
}

async fn discover(candidates: &[PathBuf], uid: u32) -> Discovery {
    let mut busy = false;
    for candidate in candidates {
        match probe_candidate(candidate, uid).await {
            Probe::Healthy => return Discovery::Healthy(candidate.clone()),
            Probe::Busy => busy = true,
            Probe::Absent => {}
        }
    }
    if busy {
        Discovery::Busy
    } else {
        Discovery::Absent
    }
}

/// Explicit paths make the actual recovery flow testable without changing
/// process-global environment or contacting the operator's daemon/fleet.
async fn recover_default_with_paths(
    config: &SelfHealingConfig,
    requested: &Path,
    candidates: &[PathBuf],
    state_dir: &Path,
    uid: u32,
    launch: impl FnOnce(&Path) -> Result<(), AutoStartError>,
) -> Result<PathBuf, AutoStartError> {
    if !config.hook_starts_daemon {
        return Err(AutoStartError::Disabled);
    }
    let budget = Duration::from_secs(config.auto_start_timeout_secs);
    if budget.is_zero() {
        return Err(AutoStartError::Timeout(config.auto_start_timeout_secs));
    }
    prepare_state_dir(state_dir, uid).map_err(AutoStartError::Io)?;
    let gate_path = state_dir.join("discovery.lock");
    let lock_path = state_dir.join("startup.lock");
    let cooldown_path = state_dir.join("startup.cooldown");
    let recovery = async {
        loop {
            let effective =
                candidates_with_record(candidates, state_dir, uid).map_err(AutoStartError::Io)?;
            // A healthy daemon can be reused even while another starter owns
            // the gate or its cooldown is active.
            if let Discovery::Healthy(path) = discover(&effective, uid).await {
                // Publishing an already-live endpoint is best-effort here:
                // lock contention must not make an available daemon unusable.
                if let Ok(_gate) = acquire_autostart_gate(&gate_path)
                    && let Err(error) = remember_endpoint(state_dir, &path)
                {
                    debug!(%error, "Could not record an already-live daemon endpoint");
                }
                return Ok(path);
            }
            let gate = match acquire_autostart_gate(&gate_path) {
                Ok(gate) => gate,
                Err(AutoStartError::LockHeld) => {
                    sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            // Re-read after acquiring ownership: another context may have
            // published an endpoint that was absent from our original list.
            let effective =
                candidates_with_record(candidates, state_dir, uid).map_err(AutoStartError::Io)?;
            match discover(&effective, uid).await {
                Discovery::Healthy(path) => {
                    remember_endpoint(state_dir, &path).map_err(AutoStartError::Io)?;
                    return Ok(path);
                }
                Discovery::Busy => {
                    // An overloaded or initializing listener still owns its
                    // endpoint. Neither unlink it nor start a competitor.
                    drop(gate);
                    sleep(Duration::from_millis(100)).await;
                }
                Discovery::Absent => {
                    recover_daemon_with_paths(
                        config,
                        requested,
                        &lock_path,
                        &cooldown_path,
                        launch,
                    )
                    .await?;
                    remember_endpoint(state_dir, requested).map_err(AutoStartError::Io)?;
                    return Ok(requested.to_path_buf());
                }
            }
        }
    };
    // Discovery, gate contention and the existing single-endpoint recovery
    // share an outer deadline; the inner recovery cannot reset that deadline.
    timeout(budget, recovery)
        .await
        .unwrap_or(Err(AutoStartError::Timeout(config.auto_start_timeout_secs)))
}

pub(super) async fn recover_daemon(
    config: &SelfHealingConfig,
    requested: &Path,
    launch: impl FnOnce(&Path) -> Result<(), AutoStartError>,
) -> Result<PathBuf, AutoStartError> {
    if !config.hook_starts_daemon {
        return Err(AutoStartError::Disabled);
    }
    if config.auto_start_timeout_secs == 0 {
        return Err(AutoStartError::Timeout(0));
    }
    // Re-read origins only on the cold recovery path. Comparing a configured
    // value with the default would incorrectly override explicit pins whose
    // value happens to equal that default. Unknown provenance stays pinned.
    // Unit tests must never discover the operator's real default endpoints.
    let allow_discovery = !cfg!(test)
        && crate::config::load_config_with_sources()
            .map(|loaded| {
                Path::new(&loaded.config.general.socket_path) == requested
                    && source_allows_discovery(loaded.sources.get("general.socket_path"))
            })
            .unwrap_or(false);
    if !allow_discovery {
        recover_daemon_with_paths(
            config,
            requested,
            &autostart_lock_path(),
            &autostart_cooldown_path(),
            launch,
        )
        .await?;
        return Ok(requested.to_path_buf());
    }
    let uid = effective_uid().map_err(AutoStartError::Io)?;
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let cache_dir = dirs::cache_dir();
    let candidates = candidates_for_context(
        requested,
        runtime_dir.as_deref(),
        cache_dir.as_deref(),
        uid,
        cfg!(target_os = "linux"),
    );
    let state_dir = PathBuf::from(format!("/tmp/rch-autostart-{uid}"));
    let resolved =
        recover_default_with_paths(config, requested, &candidates, &state_dir, uid, launch).await?;
    if resolved != requested {
        info!(
            target: "rch::hook::auto_start",
            requested_socket = %requested.display(),
            resolved_socket = %resolved.display(),
            "Reusing existing default daemon from another runtime-directory context"
        );
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UnixListener;

    /// Every listener is under a test-owned tempdir. Dropping this guard aborts
    /// the task even on an assertion failure; no real rchd or worker is used.
    struct HealthServer(tokio::task::JoinHandle<()>);

    impl Drop for HealthServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    fn health_server(path: &Path, status: &str, body: &str) -> HealthServer {
        let listener = UnixListener::bind(path).expect("bind test socket");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        HealthServer(tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = String::new();
                let read = BufReader::new(&mut stream).read_line(&mut request).await;
                if read.is_ok() {
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            }
        }))
    }

    fn healthy(path: &Path) -> HealthServer {
        health_server(path, "200 OK", r#"{"status":"healthy"}"#)
    }

    fn config() -> SelfHealingConfig {
        SelfHealingConfig {
            hook_starts_daemon: true,
            auto_start_timeout_secs: 2,
            auto_start_cooldown_secs: 30,
            ..SelfHealingConfig::default()
        }
    }

    fn no_launch(_: &Path) -> Result<(), AutoStartError> {
        panic!("recovery must not launch a competing daemon")
    }

    #[test]
    fn discovery_requires_known_default_origin() {
        assert!(source_allows_discovery(Some(&ConfigValueSource::Default)));
        assert!(!source_allows_discovery(None));
        for source in [
            ConfigValueSource::UserConfig(PathBuf::from("config.toml")),
            ConfigValueSource::ProjectConfig(PathBuf::from(".rch/config.toml")),
            ConfigValueSource::EnvVar("RCH_SOCKET_PATH".to_string()),
        ] {
            // Attribution, not path equality, protects an explicit pin even
            // when it names precisely the path the default would choose.
            assert!(!source_allows_discovery(Some(&source)));
        }
    }

    #[test]
    fn candidates_cover_both_contexts_without_duplicates() {
        let expected = vec![
            PathBuf::from("/run/user/42/rch.sock"),
            PathBuf::from("/home/example/.cache/rch/rch.sock"),
            PathBuf::from("/tmp/rch.sock"),
        ];
        assert_eq!(
            candidates_for_context(
                &expected[0],
                Some(Path::new("/run/user/42")),
                Some(Path::new("/home/example/.cache")),
                42,
                true,
            ),
            expected
        );
        assert_eq!(
            candidates_for_context(
                Path::new("/configured.sock"),
                Some(Path::new("relative-runtime")),
                Some(Path::new("relative-cache")),
                42,
                false,
            ),
            [
                PathBuf::from("/configured.sock"),
                PathBuf::from("/tmp/rch.sock")
            ]
        );
    }

    #[tokio::test]
    async fn reuses_alternate_daemon_without_launch_or_cooldown_write() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("login.sock");
        let alternate = temp.path().join("service.sock");
        let state = temp.path().join("state");
        let _server = healthy(&alternate);
        let result = recover_default_with_paths(
            &config(),
            &requested,
            &[requested.clone(), alternate.clone()],
            &state,
            effective_uid().unwrap(),
            no_launch,
        )
        .await
        .unwrap();
        assert_eq!(result, alternate);
        assert!(!requested.exists());
        assert!(!state.join("startup.cooldown").exists());
    }

    #[tokio::test]
    async fn healthy_requested_endpoint_wins_before_alternates() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("requested.sock");
        let alternate = temp.path().join("alternate.sock");
        let _requested_server = healthy(&requested);
        let _alternate_server = healthy(&alternate);
        assert_eq!(
            recover_default_with_paths(
                &config(),
                &requested,
                &[requested.clone(), alternate],
                &temp.path().join("state"),
                effective_uid().unwrap(),
                no_launch,
            )
            .await
            .unwrap(),
            requested
        );
    }

    #[tokio::test]
    async fn healthy_alternate_is_usable_during_gate_contention_and_cooldown() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("missing.sock");
        let alternate = temp.path().join("healthy.sock");
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        prepare_state_dir(&state, uid).unwrap();
        let _gate = acquire_autostart_gate(&state.join("discovery.lock")).unwrap();
        write_cooldown_timestamp(&state.join("startup.cooldown")).unwrap();
        let _server = healthy(&alternate);
        assert_eq!(
            recover_default_with_paths(
                &config(),
                &requested,
                &[requested.clone(), alternate.clone()],
                &state,
                uid,
                no_launch,
            )
            .await
            .unwrap(),
            alternate
        );
    }

    #[tokio::test]
    async fn unhealthy_live_alternate_does_not_authorize_a_second_daemon() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("missing.sock");
        let alternate = temp.path().join("unhealthy.sock");
        // A healthy-looking body inside an HTTP error must not count as ready.
        let _server = health_server(
            &alternate,
            "503 Service Unavailable",
            r#"{"status":"healthy"}"#,
        );
        let mut config = config();
        config.auto_start_timeout_secs = 1;
        let result = recover_default_with_paths(
            &config,
            &requested,
            &[requested.clone(), alternate.clone()],
            &temp.path().join("state"),
            effective_uid().unwrap(),
            no_launch,
        )
        .await;
        assert!(matches!(result, Err(AutoStartError::Timeout(1))));
        assert!(!requested.exists());
        assert!(alternate.exists(), "do not unlink the live listener");
    }

    #[tokio::test]
    async fn stale_alternate_allows_one_launch_at_the_requested_endpoint() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("new.sock");
        let stale = temp.path().join("stale.sock");
        drop(UnixListener::bind(&stale).unwrap());
        let mut server = None;
        let launches = AtomicUsize::new(0);
        let result = recover_default_with_paths(
            &config(),
            &requested,
            &[requested.clone(), stale.clone()],
            &temp.path().join("state"),
            effective_uid().unwrap(),
            |socket| {
                assert_eq!(socket, requested);
                launches.fetch_add(1, Ordering::SeqCst);
                server = Some(healthy(socket));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(result, requested);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert!(server.is_some());
        assert!(stale.exists(), "alternate stale sockets are not mutated");
    }

    #[tokio::test]
    async fn silent_listener_cannot_extend_the_probe_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("silent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let _server = HealthServer(tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        }));
        // The outer test deadline is deliberately looser than the production
        // 300ms budget. A peer that accepts but never responds remains busy.
        assert_eq!(
            timeout(
                Duration::from_secs(2),
                probe_candidate(&socket, effective_uid().unwrap()),
            )
            .await
            .expect("probe deadline must bound a silent peer"),
            Probe::Busy
        );
    }

    #[tokio::test]
    async fn concurrent_contexts_share_one_startup_owner() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.sock");
        let second = temp.path().join("second.sock");
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        let config = config();
        let first_candidates = [first.clone(), second.clone()];
        let second_candidates = [second.clone(), first.clone()];
        let launches = AtomicUsize::new(0);
        let servers = Mutex::new(Vec::new());
        let launch = |socket: &Path| {
            launches.fetch_add(1, Ordering::SeqCst);
            servers.lock().unwrap().push(healthy(socket));
            Ok(())
        };
        let (left, right) = tokio::join!(
            recover_default_with_paths(&config, &first, &first_candidates, &state, uid, launch,),
            recover_default_with_paths(&config, &second, &second_candidates, &state, uid, launch,),
        );
        assert_eq!(left.unwrap(), right.unwrap());
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disabled_and_zero_budget_recovery_have_no_state_or_spawn_side_effects() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("missing.sock");
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        let mut config = config();
        config.hook_starts_daemon = false;
        assert!(matches!(
            recover_default_with_paths(&config, &socket, &[], &state, uid, no_launch,).await,
            Err(AutoStartError::Disabled)
        ));
        config.hook_starts_daemon = true;
        config.auto_start_timeout_secs = 0;
        assert!(matches!(
            recover_default_with_paths(&config, &socket, &[], &state, uid, no_launch,).await,
            Err(AutoStartError::Timeout(0))
        ));
        assert!(!state.exists());
    }

    #[tokio::test]
    async fn alternate_probe_rejects_non_sockets_symlinks_and_wrong_owners() {
        let temp = tempfile::tempdir().unwrap();
        let uid = effective_uid().unwrap();
        let file = temp.path().join("ordinary-file");
        std::fs::write(&file, b"must remain unchanged").unwrap();
        assert_eq!(probe_candidate(&file, uid).await, Probe::Absent);
        let socket = temp.path().join("healthy.sock");
        let _server = healthy(&socket);
        let link = temp.path().join("linked.sock");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        assert_eq!(probe_candidate(&link, uid).await, Probe::Absent);
        assert_eq!(probe_candidate(&socket, uid ^ 1).await, Probe::Absent);
        assert_eq!(std::fs::read(&file).unwrap(), b"must remain unchanged");
    }

    #[tokio::test]
    async fn discovery_state_refuses_symlinks_and_shared_directories() {
        let temp = tempfile::tempdir().unwrap();
        let uid = effective_uid().unwrap();
        let shared = temp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            prepare_state_dir(&shared, uid).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let private = temp.path().join("private");
        prepare_state_dir(&private, uid).unwrap();
        let link = temp.path().join("linked");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        assert_eq!(
            prepare_state_dir(&link, uid).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::metadata(&shared).unwrap().mode() & 0o777, 0o777);
    }

    #[tokio::test]
    async fn disjoint_contexts_reuse_the_published_endpoint() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.sock");
        let second = temp.path().join("second.sock");
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        let config = config();
        let first_candidates = [first.clone()];
        let second_candidates = [second.clone()];
        let launches = AtomicUsize::new(0);
        let servers = Mutex::new(Vec::new());
        let launch = |socket: &Path| {
            launches.fetch_add(1, Ordering::SeqCst);
            servers.lock().unwrap().push(healthy(socket));
            Ok(())
        };
        let (left, right) = tokio::join!(
            recover_default_with_paths(&config, &first, &first_candidates, &state, uid, launch,),
            recover_default_with_paths(&config, &second, &second_candidates, &state, uid, launch,),
        );
        let endpoint = left.unwrap();
        assert_eq!(right.unwrap(), endpoint);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(
            parse_endpoint_record(&std::fs::read(state.join("endpoint")).unwrap()).unwrap(),
            endpoint
        );
        // A later process/context knows neither original candidate but can
        // reuse the verified record without launching another daemon.
        let third = temp.path().join("third.sock");
        assert_eq!(
            recover_default_with_paths(
                &config,
                &third,
                std::slice::from_ref(&third),
                &state,
                uid,
                no_launch,
            )
            .await
            .unwrap(),
            endpoint
        );
    }

    #[tokio::test]
    async fn stale_record_is_a_hint_not_readiness_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let stale = temp.path().join("stale.sock");
        drop(UnixListener::bind(&stale).unwrap());
        let requested = temp.path().join("current.sock");
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        prepare_state_dir(&state, uid).unwrap();
        remember_endpoint(&state, &stale).unwrap();
        let mut server = None;
        let result = recover_default_with_paths(
            &config(),
            &requested,
            std::slice::from_ref(&requested),
            &state,
            uid,
            |socket| {
                assert_eq!(socket, requested.as_path());
                server = Some(healthy(socket));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(result, requested);
        assert!(server.is_some());
        assert!(stale.exists());
        assert_eq!(
            candidates_with_record(&[], &state, uid).unwrap(),
            [requested]
        );
    }

    #[tokio::test]
    async fn unsafe_or_corrupt_record_refuses_recovery_without_a_launch() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        prepare_state_dir(&state, uid).unwrap();
        let record = state.join("endpoint");
        std::fs::write(&record, b"relative.sock").unwrap();
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        let requested = temp.path().join("new.sock");
        assert!(matches!(
            recover_default_with_paths(
                &config(),
                &requested,
                std::slice::from_ref(&requested),
                &state,
                uid,
                no_launch,
            )
            .await,
            Err(AutoStartError::Io(_))
        ));
        assert!(!requested.exists());
        assert!(!state.join("startup.cooldown").exists());
        assert_eq!(std::fs::read(record).unwrap(), b"relative.sock");
    }

    #[test]
    fn endpoint_record_parser_rejects_ambiguous_or_oversized_paths() {
        for invalid in [
            &b""[..],
            &b"relative"[..],
            &b"/tmp/\0bad"[..],
            &b"/tmp/\xff"[..],
        ] {
            assert!(parse_endpoint_record(invalid).is_err());
        }
        let oversized = format!("/{}", "x".repeat(ENDPOINT_RECORD_LIMIT as usize));
        assert!(parse_endpoint_record(oversized.as_bytes()).is_err());
        assert_eq!(
            parse_endpoint_record(b"/tmp/a socket with spaces.sock").unwrap(),
            PathBuf::from("/tmp/a socket with spaces.sock")
        );
    }

    #[tokio::test]
    async fn endpoint_record_must_be_a_private_owned_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let uid = effective_uid().unwrap();
        prepare_state_dir(&state, uid).unwrap();
        let target = temp.path().join("target");
        std::fs::write(&target, b"/tmp/other.sock").unwrap();
        std::os::unix::fs::symlink(&target, state.join("endpoint")).unwrap();
        assert!(candidates_with_record(&[], &state, uid).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"/tmp/other.sock");

        let other_state = temp.path().join("other-state");
        prepare_state_dir(&other_state, uid).unwrap();
        remember_endpoint(&other_state, Path::new("/tmp/owned.sock")).unwrap();
        assert!(candidates_with_record(&[], &other_state, uid ^ 1).is_err());
        std::fs::set_permissions(
            other_state.join("endpoint"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(candidates_with_record(&[], &other_state, uid).is_err());
    }
}
