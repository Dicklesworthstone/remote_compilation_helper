//! M4 acceptance in miniature (bridge plan Phase 1; bd-k52xe / bd-14t4j):
//! REAL `cargo build` in several worktrees of one project, every rustc
//! routed through the REAL `rabs-wrap` to a REAL `rabsd` with the live
//! dependency lane on. Nothing here hand-builds a rustc argv: Cargo plans
//! the units, chooses the flags, pipelines dependents on `.rmeta`
//! notifications and fingerprints the results, exactly as for an agent.
//!
//! Sources use both Cargo's registry layout
//! (`$CARGO_HOME/registry/src/<index>/<pkg>-<ver>`) and a separate `vendor/`
//! directory outside CARGO_HOME. Both are offline Cargo directory sources;
//! the latter must pass the live directory-source witness/capture adapter.
//!
//! What it proves:
//!
//! 1. the FIRST cold build commits every dependency without throwaway builds;
//!    later worktrees climb the same keys' verification/serving ladder;
//! 2. a later worktree's `cargo build` is served every dependency compile:
//!    the daemon answers hit -> served and admits no execution, the build
//!    succeeds, and the served `.rlib`/`.rmeta` bytes equal stock Cargo's;
//! 3. served outputs are FRESH to Cargo: an immediate rebuild reports every
//!    unit Fresh and never reaches the wrapper; editing the workspace member
//!    rebuilds only that member;
//! 4. the wall-clock of a served build versus a stock build is recorded
//!    (printed, not asserted: tiny fixtures say nothing about real crates).
//! 5. already-built large dependency metadata and a large source package
//!    both warm during a single real Cargo invocation, then reach serving.
//! 6. vendored source edits and added unlisted files miss even when Cargo's
//!    checksum document remains byte-identical; rebuilt bytes match stock.
#![cfg(target_os = "linux")]

#[path = "live_cargo_worktrees/build_script_reuse.rs"]
mod build_script_reuse;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const INDEX: &str = "index.example-0123456789abcdef";

/// Registry dependencies of the fixture project, all eligible for serving.
const DEPENDENCIES: [&str; 3] = ["leaf", "side", "middle"];

fn wrap() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-wrap")
}

#[path = "support/rabsd.rs"]
mod daemon_binary;

/// Use a prepared binary pair, or a profile-matched Cargo artifact.
fn rabsd_bin() -> PathBuf {
    daemon_binary::binary(wrap())
}

/// The real toolchain binary (`<sysroot>/bin/rustc`), not a rustup proxy.
fn real_rustc() -> PathBuf {
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("rustc --print sysroot");
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim()).join("bin/rustc")
}

struct Daemon {
    child: std::process::Child,
    log: PathBuf,
}

impl Daemon {
    fn start(root: &Path, socket: &Path) -> Self {
        let log = root.join("rabsd.log");
        let child = Command::new(rabsd_bin())
            .env("RABS_CONFIG", root.join("absent.toml"))
            .env("RABS_STATE_DIR", root.join("state"))
            .env("RABS_SOCKET_PATH", socket)
            .env("RABS_BOOT_MARKER", root.join("boot"))
            .env("RABS_LIVE_DEPENDENCY", "1")
            .env("HOME", root.join("home"))
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("spawn rabsd");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "rabsd never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { child, log }
    }

    fn decisions(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|value| value["kind"] == "rabsd-live-dependency")
            .collect()
    }

    /// Decisions after `since`, once every admitted execution in them has
    /// reached its terminal decision (publication runs on daemon time).
    fn settled_since(&self, since: usize) -> Vec<serde_json::Value> {
        const TERMINAL: [&str; 5] = [
            "committed",
            "verified",
            "quarantined",
            "not-published",
            "refused",
        ];
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let tail: Vec<_> = self.decisions().split_off(since);
            let executions = tail
                .iter()
                .filter(|decision| decision["decision"] == "execute")
                .count();
            let terminals = tail
                .iter()
                .filter(|decision| {
                    decision["decision"]
                        .as_str()
                        .is_some_and(|step| TERMINAL.contains(&step))
                })
                .count();
            if terminals >= executions || Instant::now() > deadline {
                return tail;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How many decisions of each kind a build produced, e.g. `served=2`.
fn tally(decisions: &[serde_json::Value]) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for decision in decisions {
        let label = match decision["decision"].as_str().unwrap_or("?") {
            "shadow" => format!(
                "shadow:{}",
                decision["reason"].as_str().unwrap_or("unspecified")
            ),
            other => other.to_owned(),
        };
        *counts.entry(label).or_insert(0) += 1;
    }
    counts
}

fn count(decisions: &[serde_json::Value], kind: &str) -> usize {
    decisions
        .iter()
        .filter(|decision| decision["decision"] == kind)
        .count()
}

struct World {
    root: PathBuf,
    socket: PathBuf,
    rustc: PathBuf,
    source: PathBuf,
}

impl World {
    fn new(root: &Path) -> Self {
        Self::with_source(root, root.join("cargo-home/registry/src").join(INDEX))
    }

    fn vendored(root: &Path) -> Self {
        Self::with_source(root, root.join("vendor"))
    }

    fn with_source(root: &Path, source: PathBuf) -> Self {
        let world = Self {
            root: root.to_path_buf(),
            socket: root.join("d.sock"),
            rustc: real_rustc(),
            source,
        };
        std::fs::create_dir_all(world.root.join("home")).unwrap();
        std::fs::create_dir_all(world.cargo_home()).unwrap();
        let registry = world.registry();
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(
            world.cargo_home().join("config.toml"),
            format!(
                "[source.crates-io]\nreplace-with = \"fixture\"\n\n\
                 [source.fixture]\ndirectory = \"{}\"\n\n\
                 [net]\noffline = true\n",
                registry.display()
            ),
        )
        .unwrap();
        world
    }

    fn cargo_home(&self) -> PathBuf {
        self.root.join("cargo-home")
    }

    /// Cargo's directory source, in either registry-cache or vendored layout.
    fn registry(&self) -> PathBuf {
        self.source.clone()
    }

    fn write_dependency(&self, name: &str, dependencies: &str, lib: &str) {
        let package = self.registry().join(format!("{name}-1.0.0"));
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n\
                 [dependencies]\n{dependencies}"
            ),
        )
        .unwrap();
        std::fs::write(package.join("src/lib.rs"), lib).unwrap();
        // A directory source names each file it vouches for; none is required.
        std::fs::write(package.join(".cargo-checksum.json"), "{\"files\":{}}").unwrap();
    }

    /// A fresh worktree of the same workspace project, with its own target.
    fn worktree(&self, name: &str) -> PathBuf {
        let worktree = self.root.join(name);
        std::fs::create_dir_all(worktree.join("src")).unwrap();
        std::fs::write(
            worktree.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\nmiddle = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            worktree.join("src/main.rs"),
            "fn main() { println!(\"{} {}\", middle::quad(3), middle::leaf_origin()); }\n",
        )
        .unwrap();
        worktree
    }

    fn cargo_command(&self, worktree: &Path, wrapped: bool) -> Command {
        let mut cargo = Command::new(env!("CARGO"));
        cargo
            .current_dir(worktree)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", self.root.join("home"))
            .env("CARGO_HOME", self.cargo_home())
            .env("RUSTC", &self.rustc)
            .env("CARGO_TERM_COLOR", "never")
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RABS_BREAKER_FILE", self.root.join("breaker"));
        if wrapped {
            cargo.env("RUSTC_WRAPPER", wrap());
        }
        cargo
    }

    /// `cargo build -v` as an agent would run it, with or without RABS.
    fn cargo_build(&self, worktree: &Path, wrapped: bool) -> Output {
        let output = self
            .cargo_command(worktree, wrapped)
            .args(["build", "-v"])
            .output()
            .expect("run cargo");
        assert!(
            output.status.success(),
            "cargo build failed in {}:\n{}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn run_app(worktree: &Path) -> String {
        let output = Command::new(worktree.join("target/debug/app"))
            .output()
            .expect("run app");
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }
}

/// Every regular file below `dir`, recursively.
fn files_below(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            files_below(&entry.path(), found);
        } else if kind.is_file() {
            found.push(entry.path());
        }
    }
}

/// The `.rlib`/`.rmeta` Cargo produced for `name` in a worktree, wherever
/// the build-dir layout placed them (`deps/` or per-unit `build/.../out`).
fn library_outputs(worktree: &Path, name: &str) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    files_below(&worktree.join("target/debug"), &mut found);
    let mut outputs: Vec<(String, Vec<u8>)> = found
        .into_iter()
        .filter_map(|path| {
            let file = path.file_name()?.to_str()?.to_owned();
            (file.starts_with(&format!("lib{name}-"))
                && (file.ends_with(".rlib") || file.ends_with(".rmeta")))
            .then(|| (file, std::fs::read(&path).unwrap()))
        })
        .collect();
    outputs.sort();
    assert_eq!(
        outputs.len(),
        2,
        "expected one rlib and one rmeta for {name} in {}",
        worktree.display()
    );
    outputs
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_preparing(decisions: &[serde_json::Value], reason: &str) {
    assert!(
        decisions.iter().any(|decision| {
            decision["decision"] == "preparing" && decision["reason"] == reason
        }),
        "no {reason} observation in real Cargo build: {:?}",
        tally(decisions)
    );
}

#[test]
fn real_cargo_worktrees_receive_served_dependencies_that_stay_fresh() {
    // Short root: the daemon socket path must fit sun_path.
    let dir = tempfile::Builder::new()
        .prefix("rc")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World::new(dir.path());
    let _daemon = exercise_cargo_worktrees(&world);
}

/// The exact same acceptance ladder for registry and directory-source lanes.
/// Return the daemon so the vendored case can check later source invalidation.
#[allow(clippy::too_many_lines)]
fn exercise_cargo_worktrees(world: &World) -> Daemon {
    world.write_dependency(
        "leaf",
        "",
        "#[inline]\npub fn twice(x: u32) -> u32 { x * 2 }\n\
         pub fn origin() -> &'static str { file!() }\n",
    );
    // An independent sibling: Cargo compiles it CONCURRENTLY with `leaf`,
    // both writing into the same `target/debug/deps` search directory.
    world.write_dependency(
        "side",
        "",
        "pub const OFFSET: u32 = 0;\npub fn shift(x: u32) -> u32 { x + OFFSET }\n",
    );
    world.write_dependency(
        "middle",
        "leaf = \"1.0\"\nside = \"1.0\"\n",
        "pub fn quad(x: u32) -> u32 { side::shift(leaf::twice(leaf::twice(x))) }\n\
         pub fn leaf_origin() -> &'static str { leaf::origin() }\n",
    );
    let daemon = Daemon::start(&world.root, &world.socket);

    // The oracle: stock Cargo, no wrapper. Its output is what an agent gets
    // today and what every served artifact must equal byte for byte.
    let stock = world.worktree("stock");
    let started = Instant::now();
    world.cargo_build(&stock, false);
    let stock_elapsed = started.elapsed();
    let expected_output = World::run_app(&stock);
    assert!(expected_output.starts_with("12 "), "{expected_output}");

    // 1. One FIRST cold build, not a retry-until-green warmup loop. Every
    //    dependency must wait for live facts and populate the cache in this
    //    invocation. Stock Cargo above never contacted this daemon.
    let cold = world.worktree("cold");
    let mark = daemon.decisions().len();
    let cold_build = world.cargo_build(&cold, true);
    let decisions = daemon.settled_since(mark);
    assert_preparing(&decisions, "toolchain-facts-pending");
    assert_eq!(
        (count(&decisions, "execute"), count(&decisions, "committed")),
        (DEPENDENCIES.len(), DEPENDENCIES.len()),
        "the first cold build must admit and commit every dependency: {:?}\ncargo:\n{}",
        tally(&decisions),
        stderr(&cold_build)
    );
    assert_eq!(World::run_app(&cold), expected_output);

    // Two more worktrees: the SAME keys, each a verifying execution.
    for name in ["verify-1", "verify-2"] {
        let worktree = world.worktree(name);
        let mark = daemon.decisions().len();
        world.cargo_build(&worktree, true);
        let decisions = daemon.settled_since(mark);
        assert_eq!(
            count(&decisions, "verified"),
            DEPENDENCIES.len(),
            "{name}: every dependency verifies its committed key: {:?}",
            tally(&decisions)
        );
        assert_eq!(World::run_app(&worktree), expected_output);
    }

    // 2. The served worktree: every dependency compile is answered from
    //    the cache and no compiler attempt is admitted for them.
    let served = world.worktree("served");
    let mark = daemon.decisions().len();
    let started = Instant::now();
    let build = world.cargo_build(&served, true);
    let served_elapsed = started.elapsed();
    let decisions = daemon.settled_since(mark);
    assert_eq!(
        (
            count(&decisions, "hit"),
            count(&decisions, "served"),
            count(&decisions, "execute")
        ),
        (DEPENDENCIES.len(), DEPENDENCIES.len(), 0),
        "served build decisions: {:?}\ncargo:\n{}",
        tally(&decisions),
        stderr(&build)
    );
    assert_eq!(World::run_app(&served), expected_output);
    for name in DEPENDENCIES {
        assert_eq!(
            library_outputs(&served, name),
            library_outputs(&stock, name),
            "served {name} artifacts must equal stock Cargo's"
        );
    }
    eprintln!(
        "M4 wall-clock (tiny fixture, informational): stock cargo build {stock_elapsed:?}, \
         served cargo build {served_elapsed:?}"
    );

    // 3a. Freshness: Cargo must not rebuild anything it was just served.
    let mark = daemon.decisions().len();
    let rebuild = world.cargo_build(&served, true);
    let log = stderr(&rebuild);
    for unit in DEPENDENCIES.iter().chain(&["app"]) {
        assert!(
            log.contains(&format!("Fresh {unit}")),
            "missing `Fresh {unit}` in rebuild:\n{log}"
        );
    }
    assert!(
        !log.contains("Compiling") && !log.contains("Running"),
        "a served dependency was rebuilt:\n{log}"
    );
    assert_eq!(
        daemon.decisions().len(),
        mark,
        "a fresh rebuild must not consult the daemon"
    );

    // 3b. Editing the workspace member rebuilds only the member.
    std::fs::write(
        served.join("src/main.rs"),
        "fn main() { println!(\"edited {}\", middle::quad(1)); }\n",
    )
    .unwrap();
    let edited = world.cargo_build(&served, true);
    let log = stderr(&edited);
    for name in DEPENDENCIES {
        assert!(log.contains(&format!("Fresh {name}")), "{log}");
    }
    assert!(log.contains("Compiling app"), "{log}");
    assert_eq!(World::run_app(&served), "edited 4\n");
    daemon
}

fn admitted_key(decisions: &[serde_json::Value], unit: &str) -> String {
    let executions: Vec<_> = decisions
        .iter()
        .filter(|decision| decision["decision"] == "execute" && decision["crate"] == unit)
        .collect();
    assert_eq!(executions.len(), 1, "{unit}: {decisions:?}");
    let key = executions[0]["key"].as_str().expect("admission key");
    assert!(!key.is_empty());
    assert!(
        decisions
            .iter()
            .any(|decision| decision["decision"] == "committed" && decision["key"] == key),
        "{unit} did not publish its new input identity: {decisions:?}"
    );
    key.to_owned()
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_cargo_vendored_dependencies_serve_and_invalidate_actual_source_changes() {
    let dir = tempfile::Builder::new()
        .prefix("rc-vendor")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World::vendored(dir.path());
    assert!(!world.registry().starts_with(world.cargo_home()));
    let daemon = exercise_cargo_worktrees(&world);
    let original_key = daemon
        .decisions()
        .into_iter()
        .find(|decision| decision["decision"] == "execute" && decision["crate"] == "middle")
        .expect("the cold build admitted middle")["key"]
        .as_str()
        .expect("admission key")
        .to_owned();
    let package = world.registry().join("middle-1.0.0");
    let checksum_path = package.join(".cargo-checksum.json");
    let checksum = std::fs::read(&checksum_path).unwrap();
    // The empty file map is valid Cargo directory-source input. Keep it
    // unchanged while changing what rustc actually reads: RABS must hash
    // sealed source bytes, not trust the checksum document as an oracle.
    assert_eq!(checksum, b"{\"files\":{}}");
    std::fs::write(
        package.join("src/lib.rs"),
        "pub fn quad(x: u32) -> u32 { side::shift(leaf::twice(leaf::twice(x))) + 1 }\n\
         pub fn leaf_origin() -> &'static str { leaf::origin() }\n",
    )
    .unwrap();
    let stock = world.worktree("stock-changed");
    world.cargo_build(&stock, false);
    let expected = World::run_app(&stock);
    assert!(expected.starts_with("13 "), "{expected}");
    assert_ne!(expected, World::run_app(&world.root.join("stock")));

    let changed = world.worktree("changed");
    let mark = daemon.decisions().len();
    world.cargo_build(&changed, true);
    let decisions = daemon.settled_since(mark);
    let changed_key = admitted_key(&decisions, "middle");
    assert_ne!(changed_key, original_key);
    assert_eq!(World::run_app(&changed), expected);
    assert_eq!(
        library_outputs(&changed, "middle"),
        library_outputs(&stock, "middle")
    );
    assert_eq!(std::fs::read(&checksum_path).unwrap(), checksum);

    // Negative membership is also semantic: a newly present file is an input
    // even if it is not listed by the checksum document or read by this rustc.
    std::fs::write(package.join("unlisted.txt"), b"new package member\n").unwrap();
    let added = world.worktree("added-input");
    let mark = daemon.decisions().len();
    world.cargo_build(&added, true);
    let decisions = daemon.settled_since(mark);
    assert_ne!(admitted_key(&decisions, "middle"), changed_key);
    assert_eq!(World::run_app(&added), expected);
    assert_eq!(
        library_outputs(&added, "middle"),
        library_outputs(&stock, "middle")
    );
    assert_eq!(std::fs::read(&checksum_path).unwrap(), checksum);
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_cargo_warms_large_packages_and_prebuilt_dependencies_before_execution() {
    let dir = tempfile::Builder::new()
        .prefix("rc-large")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World::new(dir.path());
    // Both the source package and the external .rmeta must cross the live
    // observer's 4 MiB synchronous budget. Non-repeating bytes avoid relying
    // on an artifact compressor retaining a large all-zero allocation.
    let mut state = 0x9e37_79b9_u32;
    let payload: Vec<u8> = (0..5 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect();
    world.write_dependency(
        "leaf",
        "",
        "pub const DATA: &[u8; 5 * 1024 * 1024] = include_bytes!(\"payload.bin\");\n\
         #[inline] pub fn twice(x: u32) -> u32 { x * 2 }\n\
         pub fn origin() -> &'static str { file!() }\n",
    );
    world.write_dependency(
        "middle",
        "leaf = \"1.0\"\n",
        "const LOCAL: &[u8] = include_bytes!(\"payload.bin\");\n\
         pub fn quad(x: u32) -> u32 {\n\
             leaf::twice(leaf::twice(x)) + u32::from(leaf::DATA[0] ^ LOCAL[0])\n\
         }\n\
         pub fn leaf_origin() -> &'static str { leaf::origin() }\n",
    );
    for name in ["leaf", "middle"] {
        std::fs::write(
            world
                .registry()
                .join(format!("{name}-1.0.0/src/payload.bin")),
            &payload,
        )
        .unwrap();
    }
    let worktree = world.worktree("prebuilt");
    world.cargo_build(&worktree, false);
    let expected_output = World::run_app(&worktree);
    assert!(expected_output.starts_with("12 "), "{expected_output}");
    let expected_artifacts = library_outputs(&worktree, "middle");
    assert!(
        library_outputs(&worktree, "leaf")
            .iter()
            .any(|(name, bytes)| name.ends_with(".rmeta") && bytes.len() > 4 * 1024 * 1024),
        "fixture must produce genuinely large compiler metadata, not synthetic dependency bytes"
    );
    // Start after stock compilation: the daemon cannot have memoized the
    // leaf's metadata via output capture. Cargo itself preserves the fresh
    // leaf while cleaning middle; no handcrafted rustc argv or fake hits.
    let daemon = Daemon::start(&world.root, &world.socket);
    for outcome in ["committed", "verified", "verified", "served"] {
        let clean = world
            .cargo_command(&worktree, false)
            .args(["clean", "-p", "middle"])
            .output()
            .expect("cargo clean middle");
        assert!(clean.status.success(), "{}", stderr(&clean));
        let mark = daemon.decisions().len();
        let build = world.cargo_build(&worktree, true);
        let decisions = daemon.settled_since(mark);
        assert!(stderr(&build).contains("Fresh leaf"), "{}", stderr(&build));
        if outcome == "committed" {
            for reason in [
                "toolchain-facts-pending",
                "package-facts-pending",
                "dependency-facts-pending",
            ] {
                assert_preparing(&decisions, reason);
            }
        }
        assert_eq!(count(&decisions, outcome), 1, "{:?}", tally(&decisions));
        assert_eq!(
            count(&decisions, "execute"),
            usize::from(outcome != "served"),
            "{:?}",
            tally(&decisions)
        );
        if outcome == "served" {
            assert_eq!(count(&decisions, "hit"), 1, "{:?}", tally(&decisions));
        }
        assert_eq!(World::run_app(&worktree), expected_output);
        assert_eq!(library_outputs(&worktree, "middle"), expected_artifacts);
    }
    let mark = daemon.decisions().len();
    let fresh = world.cargo_build(&worktree, true);
    for name in ["leaf", "middle", "app"] {
        assert!(
            stderr(&fresh).contains(&format!("Fresh {name}")),
            "{}",
            stderr(&fresh)
        );
    }
    assert_eq!(daemon.decisions().len(), mark);
}
