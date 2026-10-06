//! End-to-end proof of the live dependency lane (bd-k52xe / bd-14t4j):
//! the REAL `rabsd` (lane on), the REAL `rabs-wrap`, the REAL toolchain
//! `rustc`, and two registry packages laid out exactly as Cargo extracts
//! them (`$CARGO_HOME/registry/src/<index>/<name>-<version>`), compiled
//! into separate out-dirs the way Cargo compiles a dependency in separate
//! worktrees.
//!
//! What it proves, in order:
//!
//! 1. the first eligible compile executes as an admitted attempt and
//!    COMMITS; two more from other out-dirs VERIFY (same key);
//! 2. the next is SERVED: the daemon installs every declared output, the
//!    wrapper replays the exact transcript for its own out-dir, and the
//!    artifacts are byte-identical to what stock rustc writes;
//! 3. a consumer crate keyed on its `--extern` artifact follows the same
//!    ladder (dependency inputs are exact content, not paths);
//! 4. a changed keyed environment value, an added package file, and a
//!    compile error are all misses — the error is never published and its
//!    exit status is preserved.
//!
//! The compiler-never-ran half of "served" is proven deterministically by
//! `live_protocol.rs`; here the daemon's own decision log shows the request
//! was answered `hit` → `served` without an admitted execution.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const INDEX: &str = "index.example-0123456789abcdef";

fn wrap() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-wrap")
}

fn rabsd_bin() -> PathBuf {
    let path = Path::new(wrap()).with_file_name("rabsd");
    if !path.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "rabsd", "--bin", "rabsd"])
            .status()
            .expect("build rabsd");
        assert!(status.success());
    }
    path
}

/// The real toolchain binary (`<sysroot>/bin/rustc`), not a proxy.
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

    /// Every live-dependency decision the daemon logged, in order.
    fn decisions(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|value| value["kind"] == "rabsd-live-dependency")
            .collect()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct World {
    root: PathBuf,
    socket: PathBuf,
    rustc: PathBuf,
}

impl World {
    fn package(&self, name: &str) -> PathBuf {
        self.root
            .join("cargo-home/registry/src")
            .join(INDEX)
            .join(format!("{name}-1.0.0"))
    }

    fn write_package(&self, name: &str, lib: &str) {
        let package = self.package(name);
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(package.join(".cargo-ok"), "{\"v\":1}").unwrap();
        std::fs::write(package.join("src/lib.rs"), lib).unwrap();
    }

    fn out_dir(&self, worktree: &str) -> PathBuf {
        let out = self.root.join(worktree).join("target/debug/deps");
        std::fs::create_dir_all(&out).unwrap();
        out
    }

    /// The exact argv shape Cargo gives a registry dependency's rustc.
    fn args(&self, name: &str, out: &Path, externs: &[(&str, PathBuf)]) -> Vec<String> {
        let mut args = vec![
            "--crate-name".to_owned(),
            name.to_owned(),
            "--edition=2021".to_owned(),
            self.package(name)
                .join("src/lib.rs")
                .to_str()
                .unwrap()
                .to_owned(),
            "--error-format=json".to_owned(),
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat".to_owned(),
            "--crate-type".to_owned(),
            "lib".to_owned(),
            "--emit=dep-info,metadata,link".to_owned(),
            "-C".to_owned(),
            "embed-bitcode=no".to_owned(),
            "-C".to_owned(),
            "debuginfo=2".to_owned(),
            "-C".to_owned(),
            format!("metadata={name}0000c0ffee"),
            "-C".to_owned(),
            format!("extra-filename=-{name}0000c0ffee"),
            "--out-dir".to_owned(),
            out.to_str().unwrap().to_owned(),
            "-L".to_owned(),
            format!("dependency={}", out.display()),
        ];
        for (crate_name, path) in externs {
            args.push("--extern".to_owned());
            args.push(format!("{crate_name}={}", path.display()));
        }
        args.extend(["--cap-lints".to_owned(), "allow".to_owned()]);
        args
    }

    fn env(&self, name: &str) -> Vec<(String, String)> {
        vec![
            ("HOME".into(), self.root.join("home").display().to_string()),
            (
                "CARGO_HOME".into(),
                self.root.join("cargo-home").display().to_string(),
            ),
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            (
                "CARGO_MANIFEST_DIR".into(),
                self.package(name).display().to_string(),
            ),
            ("CARGO_PKG_NAME".into(), name.into()),
            ("CARGO_PKG_VERSION".into(), "1.0.0".into()),
            ("CARGO_CRATE_NAME".into(), name.into()),
            ("CARGO_MAKEFLAGS".into(), "-j --jobserver-fds=3,4".into()),
            // Scrubbed by dependency-env-v1: must never key or reach rustc.
            ("TERM".into(), "xterm".into()),
            ("RABS_SOCKET_PATH".into(), self.socket.display().to_string()),
            (
                "RABS_BREAKER_FILE".into(),
                self.root.join("breaker").display().to_string(),
            ),
        ]
    }

    fn wrapped(
        &self,
        name: &str,
        out: &Path,
        externs: &[(&str, PathBuf)],
        env_override: &[(&str, &str)],
    ) -> Output {
        let mut env = self.env(name);
        for (key, value) in env_override {
            env.retain(|(present, _)| present != key);
            env.push(((*key).to_owned(), (*value).to_owned()));
        }
        Command::new(wrap())
            .arg(&self.rustc)
            .args(self.args(name, out, externs))
            .current_dir(self.package(name))
            .env_clear()
            .envs(env)
            .output()
            .expect("run rabs-wrap")
    }

    /// Stock rustc, no wrapper, same argv: the oracle for served bytes.
    fn stock(&self, name: &str, out: &Path, externs: &[(&str, PathBuf)]) -> Output {
        Command::new(&self.rustc)
            .args(self.args(name, out, externs))
            .current_dir(self.package(name))
            .env_clear()
            .envs(self.env(name))
            .output()
            .expect("run rustc")
    }
}

fn outputs(name: &str) -> [String; 3] {
    [
        format!("lib{name}-{name}0000c0ffee.rlib"),
        format!("lib{name}-{name}0000c0ffee.rmeta"),
        format!("{name}-{name}0000c0ffee.d"),
    ]
}

/// Decisions logged after `since`. An admitted execution completes on the
/// daemon's own time (the wrapper never waits for publication), so the
/// trail waits for that execution's terminal decision.
fn trail(daemon: &Daemon, since: usize) -> Vec<String> {
    const TERMINAL: [&str; 5] = [
        "committed",
        "verified",
        "quarantined",
        "not-published",
        "refused",
    ];
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let trail: Vec<String> = daemon.decisions()[since..]
            .iter()
            .filter(|decision| decision["decision"] != "shadow")
            .map(|decision| decision["decision"].as_str().unwrap().to_owned())
            .collect();
        let settled = !trail.contains(&"execute".to_owned())
            || trail.iter().any(|step| TERMINAL.contains(&step.as_str()));
        if settled || Instant::now() > deadline {
            return trail;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_same_library(first: &Path, second: &Path, name: &str) {
    for file in &outputs(name)[..2] {
        assert_eq!(
            std::fs::read(first.join(file)).unwrap(),
            std::fs::read(second.join(file)).unwrap(),
            "{file} differs between {} and {}",
            first.display(),
            second.display()
        );
    }
    let dep_info = &outputs(name)[2];
    let first_d = String::from_utf8(std::fs::read(first.join(dep_info)).unwrap()).unwrap();
    let second_d = String::from_utf8(std::fs::read(second.join(dep_info)).unwrap()).unwrap();
    assert_eq!(
        first_d.replace(first.to_str().unwrap(), "<OUT>"),
        second_d.replace(second.to_str().unwrap(), "<OUT>"),
        "dep-info differs beyond the out-dir"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn registry_dependencies_commit_verify_and_serve_byte_identical_results() {
    // Short root: the daemon socket path must fit sun_path.
    let dir = tempfile::Builder::new()
        .prefix("rl")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World {
        root: dir.path().to_path_buf(),
        socket: dir.path().join("d.sock"),
        rustc: real_rustc(),
    };
    world.write_package(
        "leaf",
        "#[inline]\npub fn twice(x: u32) -> u32 { x * 2 }\n\
         pub fn origin() -> &'static str { file!() }\n",
    );
    world.write_package(
        "demo",
        "pub fn quad(x: u32) -> u32 { leaf::twice(leaf::twice(x)) }\n\
         pub fn version() -> &'static str { env!(\"CARGO_PKG_VERSION\") }\n",
    );
    let daemon = Daemon::start(&world.root, &world.socket);

    // 1. Warm the toolchain probe (background hashing of the sysroot), then
    //    the first eligible compile executes and commits.
    let out_a = world.out_dir("wt-a");
    let deadline = Instant::now() + Duration::from_secs(600);
    let committed_a = loop {
        let mark = daemon.decisions().len();
        let output = world.wrapped("leaf", &out_a, &[], &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let trail = trail(&daemon, mark);
        if trail.contains(&"committed".to_owned()) {
            assert_eq!(trail, ["execute", "committed"]);
            break output;
        }
        assert!(
            trail.iter().all(|step| step == "toolchain-warming"),
            "unexpected decisions while warming: {trail:?}"
        );
        assert!(Instant::now() < deadline, "toolchain probe never warmed");
        std::thread::sleep(Duration::from_millis(250));
    };
    let key = daemon
        .decisions()
        .iter()
        .rev()
        .find(|decision| decision["decision"] == "committed")
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_owned();

    // Two more out-dirs: the SAME key, each appending verification evidence.
    for worktree in ["wt-b", "wt-c"] {
        let mark = daemon.decisions().len();
        let output = world.wrapped("leaf", &world.out_dir(worktree), &[], &[]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(trail(&daemon, mark), ["execute", "verified"], "{worktree}");
        assert!(
            daemon.decisions()[mark..]
                .iter()
                .all(|decision| decision["key"].as_str().is_none_or(|k| k == key))
        );
    }

    // 2. Served: installed by the daemon, transcript replayed, no execution.
    let out_d = world.out_dir("wt-d");
    let mark = daemon.decisions().len();
    let served = world.wrapped("leaf", &out_d, &[], &[]);
    assert_eq!(served.status.code(), Some(0));
    assert_eq!(trail(&daemon, mark), ["hit", "served"]);
    assert!(served.stdout.is_empty());
    assert_eq!(
        String::from_utf8(served.stderr.clone()).unwrap(),
        String::from_utf8(committed_a.stderr.clone())
            .unwrap()
            .replace(out_a.to_str().unwrap(), out_d.to_str().unwrap()),
        "the replayed transcript is the compiler's, for THIS out-dir"
    );
    assert!(
        String::from_utf8_lossy(&served.stderr).contains("\"emit\":\"metadata\""),
        "artifact notifications (Cargo pipelining) are replayed"
    );
    assert_same_library(&out_a, &out_d, "leaf");
    // The oracle: stock rustc, same argv, fresh out-dir.
    let out_stock = world.out_dir("stock");
    assert_eq!(world.stock("leaf", &out_stock, &[]).status.code(), Some(0));
    assert_same_library(&out_stock, &out_d, "leaf");

    // 3. A consumer keyed on its exact extern bytes climbs the same ladder.
    let leaf_rmeta = |out: &Path| ("leaf", out.join(&outputs("leaf")[1]));
    let mut demo_trails = Vec::new();
    for out in [
        &out_a,
        &world.out_dir("wt-b"),
        &world.out_dir("wt-c"),
        &out_d,
    ] {
        let mark = daemon.decisions().len();
        let output = world.wrapped("demo", out, &[leaf_rmeta(out)], &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        demo_trails.push(trail(&daemon, mark));
    }
    assert_eq!(
        demo_trails,
        [
            vec!["execute", "committed"],
            vec!["execute", "verified"],
            vec!["execute", "verified"],
            vec!["hit", "served"],
        ]
    );
    assert_same_library(&out_a, &out_d, "demo");
    assert_eq!(
        world
            .stock("demo", &out_stock, &[leaf_rmeta(&out_stock)])
            .status
            .code(),
        Some(0)
    );
    assert_same_library(&out_stock, &out_d, "demo");

    // 4a. A keyed environment value is part of the key: miss, new commit.
    let mark = daemon.decisions().len();
    let out_e = world.out_dir("wt-e");
    let output = world.wrapped("leaf", &out_e, &[], &[("CARGO_PKG_VERSION", "1.0.1")]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(trail(&daemon, mark), ["execute", "committed"]);
    // A scrubbed one is not: still a hit.
    let mark = daemon.decisions().len();
    let output = world.wrapped("leaf", &world.out_dir("wt-f"), &[], &[("TERM", "dumb")]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(trail(&daemon, mark), ["hit", "served"]);

    // 4b. Any added package file changes the complete-tree key.
    std::fs::write(world.package("leaf").join("src/unused.rs"), "// new\n").unwrap();
    let mark = daemon.decisions().len();
    let output = world.wrapped("leaf", &world.out_dir("wt-g"), &[], &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(trail(&daemon, mark), ["execute", "committed"]);

    // 4c. A compile error: exit status and diagnostics preserved, nothing
    //     published, and the next attempt is a fresh execution.
    world.write_package("broken", "pub fn f() -> u32 { \"not a number\" }\n");
    for _ in 0..2 {
        let mark = daemon.decisions().len();
        let output = world.wrapped("broken", &world.out_dir("wt-h"), &[], &[]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("mismatched types"));
        assert_eq!(trail(&daemon, mark), ["execute", "not-published"]);
    }
}
