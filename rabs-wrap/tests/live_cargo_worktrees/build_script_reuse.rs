//! Real-Cargo acceptance for the opt-in empty-OUT_DIR key projection.
//! Uses the parent suite's offline source, stock compiler and artifact oracle.
//! No synthetic compiler outputs, preseeded CAS objects or relaxed trust gates.

use super::*;

const CONFIG_SCRIPT: &str = r#"
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(configured)");
    println!("cargo::rustc-cfg=configured");
    println!("cargo::rustc-env=BUILD_LABEL=ready");
}
"#;

fn daemon_with_reuse(world: &World) -> Daemon {
    let log = world.root.join("rabsd.log");
    let child = Command::new(rabsd_bin())
        .env("RABS_CONFIG", world.root.join("absent.toml"))
        .env("RABS_STATE_DIR", world.root.join("state"))
        .env("RABS_SOCKET_PATH", &world.socket)
        .env("RABS_BOOT_MARKER", world.root.join("boot"))
        .env("RABS_LIVE_DEPENDENCY", "1")
        .env("RABS_REUSE_EMPTY_OUT_DIR", "1")
        .env("HOME", world.root.join("home"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("spawn rabsd with empty-OUT_DIR reuse");
    // Own the child before readiness assertions: unwinding must reap it too.
    let mut daemon = Daemon { child, log };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !world.socket.exists() {
        assert!(
            daemon.child.try_wait().unwrap().is_none(),
            "daemon exited during startup"
        );
        assert!(Instant::now() < deadline, "daemon never listened");
        std::thread::sleep(Duration::from_millis(20));
    }
    daemon
}

fn script_dependency(world: &World, source: &str, script: &str) {
    world.write_dependency("middle", "", source);
    std::fs::write(world.registry().join("middle-1.0.0/build.rs"), script).unwrap();
}

/// Cargo's own JSON reports the actual build-script directory. It is not a
/// guessed target-layout path or a value we inject into the wrapper request.
fn json_build(world: &World, worktree: &Path, wrapped: bool) -> (Output, PathBuf) {
    let output = world
        .cargo_command(worktree, wrapped)
        .args(["build", "-v", "--message-format=json"])
        .output()
        .expect("real cargo build");
    assert!(output.status.success(), "{}", stderr(&output));
    let records: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("Cargo JSON record"))
        .collect();
    let scripts: Vec<_> = records
        .iter()
        .filter(|record| record["reason"] == "build-script-executed")
        .collect();
    assert_eq!(scripts.len(), 1, "fixture has exactly one build script");
    let generated = PathBuf::from(scripts[0]["out_dir"].as_str().unwrap());
    assert!(generated.starts_with(worktree), "{}", generated.display());
    (output, generated)
}

fn request_key(decisions: &[serde_json::Value], decision: &str) -> String {
    let keys: Vec<_> = decisions
        .iter()
        .filter(|record| record["decision"] == decision && record["crate"] == "middle")
        .map(|record| record["key"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(keys.len(), 1, "{:?}", tally(decisions));
    keys[0].clone()
}

#[test]
fn config_only_build_script_compiles_are_served_across_real_cargo_worktrees() {
    let dir = tempfile::Builder::new()
        .prefix("rc-cfg")
        .tempdir_in("/tmp")
        .unwrap();
    // Exercise the new directory-source adapter as well as build-script reuse.
    let world = World::vendored(dir.path());
    script_dependency(
        &world,
        concat!(
            "#[cfg(configured)] pub fn quad(x: u32) -> u32 { x * 4 }\n",
            "#[cfg(not(configured))] compile_error!(\"missing build-script cfg\");\n",
            "pub fn leaf_origin() -> &'static str { env!(\"BUILD_LABEL\") }\n",
        ),
        CONFIG_SCRIPT,
    );
    let stock = world.worktree("stock");
    let (_, stock_generated) = json_build(&world, &stock, false);
    assert_eq!(std::fs::read_dir(&stock_generated).unwrap().count(), 0);
    assert_eq!(World::run_app(&stock), "12 ready\n");
    let expected = library_outputs(&stock, "middle");
    let daemon = daemon_with_reuse(&world);
    let mut original_key = None;
    let mut generated_roots = std::collections::BTreeSet::new();
    for (name, outcome) in [
        ("cold", "committed"),
        ("verify-one", "verified"),
        ("verify-two", "verified"),
        ("served", "served"),
    ] {
        let worktree = world.worktree(name);
        let mark = daemon.decisions().len();
        let (build, generated) = json_build(&world, &worktree, true);
        assert!(generated_roots.insert(generated.clone()));
        assert_eq!(std::fs::read_dir(&generated).unwrap().count(), 0);
        // Every worktree runs its build script normally, even the served one.
        assert!(
            stderr(&build).lines().any(|line| {
                line.contains("Running")
                    && (line.contains("/build-script-build")
                        || line.contains("/build_script_build"))
            }),
            "build script must execute in {name}: {}",
            stderr(&build)
        );
        let decisions = daemon.settled_since(mark);
        assert_eq!(count(&decisions, outcome), 1, "{:?}", tally(&decisions));
        assert_eq!(
            count(&decisions, "execute"),
            usize::from(outcome != "served"),
            "{:?}",
            tally(&decisions)
        );
        assert_eq!(count(&decisions, "hit"), usize::from(outcome == "served"));
        let key = request_key(
            &decisions,
            if outcome == "served" {
                "hit"
            } else {
                "execute"
            },
        );
        if let Some(expected) = &original_key {
            assert_eq!(&key, expected, "OUT_DIR placement must not fork this key");
        } else {
            original_key = Some(key);
        }
        assert_eq!(World::run_app(&worktree), "12 ready\n");
        assert_eq!(library_outputs(&worktree, "middle"), expected);
    }
    let served = world.root.join("served");
    let mark = daemon.decisions().len();
    let fresh = world.cargo_build(&served, true);
    for unit in ["middle", "app"] {
        assert!(
            stderr(&fresh).contains(&format!("Fresh {unit}")),
            "{}",
            stderr(&fresh)
        );
    }
    assert!(!stderr(&fresh).contains("Running"), "{}", stderr(&fresh));
    assert_eq!(daemon.decisions().len(), mark);
}

#[test]
fn tracked_out_dir_reads_never_become_cross_worktree_cache_hits() {
    for expression in ["env!(\"OUT_DIR\")", "option_env!(\"OUT_DIR\").unwrap()"] {
        let dir = tempfile::Builder::new()
            .prefix("rc-read")
            .tempdir_in("/tmp")
            .unwrap();
        let world = World::new(dir.path());
        script_dependency(
            &world,
            &format!(
                "pub fn quad(x: u32) -> u32 {{ x * 4 }}\n\
                 pub fn leaf_origin() -> &'static str {{ {expression} }}\n"
            ),
            CONFIG_SCRIPT,
        );
        let daemon = daemon_with_reuse(&world);
        let mut original_key = None;
        // Four successes would normally reach serving. All four must instead
        // execute: the compiler's real dep-info prevents projected publication.
        for index in 0..4 {
            let worktree = world.worktree(&format!("read-{index}"));
            let mark = daemon.decisions().len();
            let (_, generated) = json_build(&world, &worktree, true);
            assert_eq!(std::fs::read_dir(&generated).unwrap().count(), 0);
            assert_eq!(
                World::run_app(&worktree),
                format!("12 {}\n", generated.display())
            );
            // Capture rejection has no publication task to settle. Request
            // decisions precede compiler execution and are already recorded.
            let decisions = daemon.decisions().split_off(mark);
            assert_eq!(count(&decisions, "execute"), 1, "{:?}", tally(&decisions));
            assert_eq!(count(&decisions, "hit"), 0, "{:?}", tally(&decisions));
            for forbidden in ["committed", "verified", "served"] {
                assert_eq!(count(&decisions, forbidden), 0, "{:?}", tally(&decisions));
            }
            let key = request_key(&decisions, "execute");
            if let Some(expected) = &original_key {
                assert_eq!(
                    &key, expected,
                    "test must exercise the projected key, not exact-path misses"
                );
            } else {
                original_key = Some(key);
            }
        }
    }
}

#[test]
fn generated_file_consumers_keep_the_exact_path_lane_with_reuse_enabled() {
    let dir = tempfile::Builder::new()
        .prefix("rc-gen")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World::new(dir.path());
    script_dependency(
        &world,
        concat!(
            "include!(concat!(env!(\"OUT_DIR\"), \"/value.rs\"));\n",
            "pub fn quad(x: u32) -> u32 { x * 4 }\n",
            "pub fn leaf_origin() -> &'static str { LABEL }\n",
        ),
        r#"
fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("value.rs"), "const LABEL: &str = \"generated\";\n").unwrap();
    println!("cargo::rerun-if-changed=build.rs");
}
"#,
    );
    let daemon = daemon_with_reuse(&world);
    let mut keys = Vec::new();
    for name in ["generated-one", "generated-two"] {
        let worktree = world.worktree(name);
        let mark = daemon.decisions().len();
        let (_, generated) = json_build(&world, &worktree, true);
        assert!(generated.join("value.rs").is_file());
        let decisions = daemon.settled_since(mark);
        assert_eq!(count(&decisions, "execute"), 1, "{:?}", tally(&decisions));
        assert_eq!(count(&decisions, "committed"), 1, "{:?}", tally(&decisions));
        assert_eq!(count(&decisions, "hit"), 0);
        keys.push(request_key(&decisions, "execute"));
        assert_eq!(World::run_app(&worktree), "12 generated\n");
    }
    assert_ne!(
        keys[0], keys[1],
        "generated-input paths remain semantic inputs"
    );
}
