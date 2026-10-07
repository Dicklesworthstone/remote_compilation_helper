//! End-to-end proof of the live dependency lane (bd-k52xe / bd-14t4j):
//! the REAL `rabsd` (lane on), the REAL `rabs-wrap`, the REAL toolchain
//! `rustc`, registry packages laid out as Cargo extracts them, and a real
//! local Git workspace fetched by Cargo at a pinned revision. They compile
//! into separate out-dirs the way Cargo compiles dependencies in separate
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
//! 5. a nested Git workspace member follows the same live ladder; sibling
//!    bytes and new checkout files key it, while Git metadata never becomes
//!    an admitted compiler input.
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
    git_checkout: Option<PathBuf>,
}

impl World {
    fn package(&self, name: &str) -> PathBuf {
        if let Some(checkout) = &self.git_checkout {
            return checkout.join("crates").join(name);
        }
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

    /// The exact argv shape Cargo gives a dependency's rustc.
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
        if self.git_checkout.is_some() {
            // The pinned Cargo's actual Git dependency invocation emits
            // separate rmeta and omits metadata from its rlib.
            args.extend(["-Z".to_owned(), "embed-metadata=no".to_owned()]);
        }
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

    /// [`World::args`] with Cargo's real `-{16 hex}` extra filename.
    fn cargo_args(&self, name: &str, out: &Path, externs: &[(&str, PathBuf)]) -> Vec<String> {
        self.args(name, out, externs)
            .into_iter()
            .map(|arg| {
                let mut arg = arg;
                for crate_name in ["leaf", "mid", "top"] {
                    arg = arg.replace(&format!("{crate_name}0000c0ffee"), cargo_hash(crate_name));
                }
                arg
            })
            .collect()
    }

    fn wrapped_cargo(&self, name: &str, out: &Path, externs: &[(&str, PathBuf)]) -> Output {
        Command::new(wrap())
            .arg(&self.rustc)
            .args(self.cargo_args(name, out, externs))
            .current_dir(self.package(name))
            .env_clear()
            .envs(self.env(name))
            .output()
            .expect("run rabs-wrap")
    }

    fn stock_cargo(&self, name: &str, out: &Path, externs: &[(&str, PathBuf)]) -> Output {
        Command::new(&self.rustc)
            .args(self.cargo_args(name, out, externs))
            .current_dir(self.package(name))
            .env_clear()
            .envs(self.env(name))
            .output()
            .expect("run rustc")
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

    /// Fetch a real committed workspace through Cargo's Git resolver.
    /// The live requests below compile the resulting nested package with
    /// the same wrapper/daemon machinery as the registry test.
    #[allow(clippy::too_many_lines)]
    fn fetch_git_workspace(&mut self) -> PathBuf {
        let upstream = self.root.join("upstream");
        let package = upstream.join("crates/leaf");
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::write(
            upstream.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/leaf\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"leaf\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            package.join("src/lib.rs"),
            "pub fn readme() -> &'static str { include_str!(\"../../../README.md\") }\n\
             pub fn origin() -> &'static str { file!() }\n",
        )
        .unwrap();
        std::fs::write(upstream.join("README.md"), "first\n").unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .current_dir(&upstream)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "RABS fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
                .env("GIT_COMMITTER_NAME", "RABS fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
                .output()
                .expect("run local Git fixture command");
            assert!(output.status.success(), "git {args:?}: {output:?}");
            output
        };
        git(&["init", "--quiet"]);
        git(&["add", "Cargo.toml", "README.md", "crates"]);
        git(&["commit", "--quiet", "-m", "dependency fixture"]);
        let revision = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned();

        let consumer = self.root.join("consumer");
        std::fs::create_dir_all(consumer.join("src")).unwrap();
        std::fs::write(
            consumer.join("Cargo.toml"),
            format!(
                "[package]\nname = \"consumer\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\nleaf = {{ git = \"file://{}\", rev = \"{revision}\" }}\n",
                upstream.display()
            ),
        )
        .unwrap();
        std::fs::write(consumer.join("src/lib.rs"), "pub use leaf::readme;\n").unwrap();
        let output = Command::new(env!("CARGO"))
            .args(["metadata", "--format-version", "1"])
            .current_dir(&consumer)
            .env("CARGO_HOME", self.root.join("cargo-home"))
            .env("RUSTC", &self.rustc)
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .output()
            .expect("resolve the pinned local Git dependency with Cargo");
        assert!(output.status.success(), "cargo metadata: {output:?}");
        let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let leaf = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == "leaf")
            .expect("Cargo resolved the Git workspace member");
        assert!(
            leaf["source"]
                .as_str()
                .unwrap()
                .ends_with(&format!("#{revision}"))
        );
        let manifest = PathBuf::from(leaf["manifest_path"].as_str().unwrap());
        let checkout = manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(checkout.starts_with(self.root.join("cargo-home/git/checkouts")));
        assert!(checkout.join(".git").is_dir());
        assert_eq!(manifest, checkout.join("crates/leaf/Cargo.toml"));
        self.git_checkout = Some(checkout.clone());
        checkout
    }
}

/// A Cargo-shaped extra-filename hash for the busy-directory scenario.
fn cargo_hash(name: &str) -> &'static str {
    match name {
        "leaf" => "6c65616600000000",
        "mid" => "6d69640000000000",
        "top" => "746f700000000000",
        other => panic!("no hash for {other}"),
    }
}

fn cargo_outputs(name: &str) -> [String; 3] {
    let hash = cargo_hash(name);
    [
        format!("lib{name}-{hash}.rlib"),
        format!("lib{name}-{hash}.rmeta"),
        format!("{name}-{hash}.d"),
    ]
}

/// What a long-lived target directory and a concurrent `cargo -jN` put
/// beside the crates a compile actually reads: other crates, an unrelated
/// proc-macro, test executables, rustc temporaries and stale versions.
fn make_busy(out: &Path) {
    std::fs::write(
        out.join("libother-0123456789abcdef.rmeta"),
        b"unrelated crate",
    )
    .unwrap();
    std::fs::write(
        out.join("libmacro-fedcba9876543210.so"),
        b"\x7fELF unrelated proc-macro",
    )
    .unwrap();
    std::fs::write(out.join("proj-1111111111111111"), b"test executable").unwrap();
    std::fs::write(out.join("proj-1111111111111111.d"), b"dep-info").unwrap();
    std::fs::write(
        out.join("x-2222222222222222.x.1a2b-cgu.0.rcgu.o"),
        b"object",
    )
    .unwrap();
    std::fs::create_dir_all(out.join("rmetaTmp123")).unwrap();
    std::fs::write(
        out.join("libleaf-0000000000000000.rlib"),
        b"stale other version",
    )
    .unwrap();
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
        git_checkout: None,
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

#[test]
#[allow(clippy::too_many_lines)]
fn git_workspace_dependency_commits_verifies_and_serves_with_a_complete_source_closure() {
    let dir = tempfile::Builder::new()
        .prefix("gl")
        .tempdir_in("/tmp")
        .unwrap();
    let mut world = World {
        root: dir.path().to_path_buf(),
        socket: dir.path().join("d.sock"),
        rustc: real_rustc(),
        git_checkout: None,
    };
    let checkout = world.fetch_git_workspace();
    let daemon = Daemon::start(&world.root, &world.socket);

    let out_a = world.out_dir("wt-a");
    let deadline = Instant::now() + Duration::from_secs(600);
    let committed = loop {
        let mark = daemon.decisions().len();
        let output = world.wrapped("leaf", &out_a, &[], &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let decisions = trail(&daemon, mark);
        if decisions.contains(&"committed".to_owned()) {
            assert_eq!(decisions, ["execute", "committed"]);
            break output;
        }
        assert!(
            decisions.iter().all(|step| step == "toolchain-warming"),
            "unexpected decisions while warming: {decisions:?}"
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

    // Git actions acquire their own evidence through real compiler runs;
    // the extension cannot borrow registry samples or bypass the floor.
    for worktree in ["wt-b", "wt-c"] {
        let mark = daemon.decisions().len();
        let output = world.wrapped("leaf", &world.out_dir(worktree), &[], &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(trail(&daemon, mark), ["execute", "verified"]);
        assert!(
            daemon.decisions()[mark..]
                .iter()
                .all(|decision| decision["key"].as_str().is_none_or(|seen| seen == key))
        );
    }

    // Git bookkeeping is outside the source closure. A new metadata file
    // must not force a miss or get copied into a source snapshot.
    std::fs::write(
        checkout.join(".git/rabs-private-input"),
        "private metadata\n",
    )
    .unwrap();
    let out_served = world.out_dir("served");
    let mark = daemon.decisions().len();
    let served = world.wrapped("leaf", &out_served, &[], &[]);
    assert_eq!(served.status.code(), Some(0), "{served:?}");
    assert_eq!(trail(&daemon, mark), ["hit", "served"]);
    assert!(served.stdout.is_empty());
    assert_eq!(
        String::from_utf8(served.stderr.clone()).unwrap(),
        String::from_utf8(committed.stderr)
            .unwrap()
            .replace(out_a.to_str().unwrap(), out_served.to_str().unwrap()),
        "the Git hit replays the actual transcript at the subscriber out-dir"
    );
    assert!(String::from_utf8_lossy(&served.stderr).contains("\"emit\":\"metadata\""));
    assert_same_library(&out_a, &out_served, "leaf");
    let out_stock = world.out_dir("stock");
    let stock = world.stock("leaf", &out_stock, &[]);
    assert_eq!(stock.status.code(), Some(0), "{stock:?}");
    assert_same_library(&out_stock, &out_served, "leaf");

    // The included README is outside crates/leaf but inside the checkout.
    // Its equal-length dirty edit changes the key and the actual library.
    std::fs::write(checkout.join("README.md"), "other\n").unwrap();
    let out_dirty = world.out_dir("dirty");
    let mark = daemon.decisions().len();
    let dirty = world.wrapped("leaf", &out_dirty, &[], &[]);
    assert_eq!(dirty.status.code(), Some(0), "{dirty:?}");
    assert_eq!(trail(&daemon, mark), ["execute", "committed"]);
    assert!(
        daemon.decisions()[mark..]
            .iter()
            .filter_map(|decision| decision["key"].as_str())
            .all(|seen| seen != key)
    );
    assert_ne!(
        std::fs::read(out_dirty.join(&outputs("leaf")[0])).unwrap(),
        std::fs::read(out_served.join(&outputs("leaf")[0])).unwrap(),
        "the compiler consumed the changed sibling bytes"
    );
    let out_dirty_stock = world.out_dir("dirty-stock");
    assert_eq!(
        world.stock("leaf", &out_dirty_stock, &[]).status.code(),
        Some(0)
    );
    assert_same_library(&out_dirty_stock, &out_dirty, "leaf");

    // Restored bytes recover the original verified key; Git status and
    // mtimes are not substitutes for content identity.
    std::fs::write(checkout.join("README.md"), "first\n").unwrap();
    let out_restored = world.out_dir("restored");
    let mark = daemon.decisions().len();
    let restored = world.wrapped("leaf", &out_restored, &[], &[]);
    assert_eq!(restored.status.code(), Some(0), "{restored:?}");
    assert_eq!(trail(&daemon, mark), ["hit", "served"]);
    assert_same_library(&out_served, &out_restored, "leaf");

    // Even an untracked file which this crate does not read changes the
    // complete checkout enumeration and starts a new evidence history.
    std::fs::write(checkout.join("untracked.txt"), "new source member\n").unwrap();
    let mark = daemon.decisions().len();
    let added = world.wrapped("leaf", &world.out_dir("added"), &[], &[]);
    assert_eq!(added.status.code(), Some(0), "{added:?}");
    assert_eq!(trail(&daemon, mark), ["execute", "committed"]);

    // Normal rustc can read the metadata, but this lane cannot publish
    // that result. A second request still executes; no candidate was
    // silently promoted from an unkeyed metadata read.
    std::fs::write(
        world.package("leaf").join("src/lib.rs"),
        "pub fn private_input() -> &'static str {\n\
         include_str!(\"../../../.git/rabs-private-input\")\n}\n",
    )
    .unwrap();
    for worktree in ["metadata-a", "metadata-b"] {
        let mark = daemon.decisions().len();
        let output = world.wrapped("leaf", &world.out_dir(worktree), &[], &[]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(trail(&daemon, mark), ["execute", "not-published"]);
        assert!(daemon.decisions()[mark..].iter().any(|decision| {
            decision["decision"] == "not-published"
                && decision["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("Git metadata"))
        }));
    }
}

/// Real Cargo target directories are never clean: they hold every crate,
/// test executable and proc-macro a project built, and a parallel build
/// writes siblings while a compile runs. Only the files rustc's crate
/// locator can examine key a compile, so busy worktrees still verify and
/// hit, and a transitive dependency whose `.rlib` pipelining has not
/// written yet keys the same as one whose `.rlib` exists.
#[test]
#[allow(clippy::too_many_lines)]
fn busy_target_directories_and_transitive_dependencies_still_serve() {
    let dir = tempfile::Builder::new()
        .prefix("rb")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World {
        root: dir.path().to_path_buf(),
        socket: dir.path().join("d.sock"),
        rustc: real_rustc(),
        git_checkout: None,
    };
    world.write_package(
        "leaf",
        "#[inline]\npub fn twice<T: core::ops::Add<Output = T> + Copy>(x: T) -> T { x + x }\n",
    );
    world.write_package(
        "mid",
        "pub use leaf::twice;\npub fn four() -> u32 { twice(2) }\n",
    );
    // top names only mid; leaf is located transitively through mid's metadata.
    world.write_package("top", "pub fn eight() -> u32 { mid::twice(mid::four()) }\n");
    let daemon = Daemon::start(&world.root, &world.socket);
    let rmeta = |name: &'static str, out: &Path| (name, out.join(&cargo_outputs(name)[1]));
    let build = |name: &'static str, out: &Path| -> Vec<String> {
        let externs: Vec<(&str, PathBuf)> = match name {
            "mid" => vec![rmeta("leaf", out)],
            "top" => vec![rmeta("mid", out)],
            _ => Vec::new(),
        };
        let mark = daemon.decisions().len();
        let output = world.wrapped_cargo(name, out, &externs);
        assert_eq!(output.status.code(), Some(0), "{name}: {output:?}");
        trail(&daemon, mark)
    };

    // Warm the toolchain probe with the first eligible compile.
    let out_a = world.out_dir("wt-a");
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let trail = build("leaf", &out_a);
        if trail.contains(&"committed".to_owned()) {
            assert_eq!(trail, ["execute", "committed"]);
            break;
        }
        assert!(
            trail.iter().all(|step| step == "toolchain-warming"),
            "unexpected decisions while warming: {trail:?}"
        );
        assert!(Instant::now() < deadline, "toolchain probe never warmed");
        std::thread::sleep(Duration::from_millis(250));
    }
    for name in ["mid", "top"] {
        assert_eq!(build(name, &out_a), ["execute", "committed"], "{name}");
    }

    // Busy worktrees verify under the same keys.
    for worktree in ["wt-b", "wt-c"] {
        let out = world.out_dir(worktree);
        make_busy(&out);
        for name in ["leaf", "mid", "top"] {
            assert_eq!(
                build(name, &out),
                ["execute", "verified"],
                "{worktree} {name}"
            );
        }
    }

    // A busy worktree is served every crate.
    let out_d = world.out_dir("wt-d");
    make_busy(&out_d);
    for name in ["leaf", "mid", "top"] {
        assert_eq!(build(name, &out_d), ["hit", "served"], "{name}");
    }

    // Pipelining: top starts while leaf's rlib does not exist yet.
    let out_e = world.out_dir("wt-e");
    make_busy(&out_e);
    for name in ["leaf", "mid"] {
        assert_eq!(build(name, &out_e), ["hit", "served"], "{name}");
    }
    std::fs::remove_file(out_e.join(&cargo_outputs("leaf")[0])).unwrap();
    assert_eq!(build("top", &out_e), ["hit", "served"]);

    // Served bytes equal stock rustc's, compiled in a clean directory.
    let out_stock = world.out_dir("stock");
    for name in ["leaf", "mid", "top"] {
        let externs: Vec<(&str, PathBuf)> = match name {
            "mid" => vec![rmeta("leaf", &out_stock)],
            "top" => vec![rmeta("mid", &out_stock)],
            _ => Vec::new(),
        };
        let stock = world.stock_cargo(name, &out_stock, &externs);
        assert_eq!(stock.status.code(), Some(0), "{stock:?}");
        for out in [&out_d, &out_e] {
            for file in &cargo_outputs(name)[..2] {
                if !out.join(file).exists() {
                    continue; // leaf's rlib was removed in wt-e
                }
                assert_eq!(
                    std::fs::read(out.join(file)).unwrap(),
                    std::fs::read(out_stock.join(file)).unwrap(),
                    "{file} in {} differs from stock",
                    out.display()
                );
            }
        }
    }

    // A transitive dependency whose metadata differs IS a different key:
    // rebuild leaf in a fresh worktree from changed source.
    world.write_package(
        "leaf",
        "#[inline]\npub fn twice<T: core::ops::Add<Output = T> + Copy>(x: T) -> T { let y = x; y + x }\n",
    );
    let out_f = world.out_dir("wt-f");
    assert_eq!(build("leaf", &out_f), ["execute", "committed"]);
    assert_eq!(build("mid", &out_f), ["execute", "committed"]);
    assert_eq!(build("top", &out_f), ["execute", "committed"]);
}

/// Cargo's record of one build-script run in a worktree, in the build-dir
/// layout the pinned Cargo writes: `build/<pkg>/<hash>/{out/, run/stdout,
/// run/root-output}`. Returns `OUT_DIR`.
fn build_script_record(worktree: &Path, name: &str, stdout: &str) -> PathBuf {
    let unit = worktree.join(format!("target/debug/build/{name}/0123456789abcdef"));
    let out = unit.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(unit.join("run")).unwrap();
    std::fs::write(unit.join("run/stdout"), stdout).unwrap();
    std::fs::write(
        unit.join("run/root-output"),
        out.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    out
}

/// A package with a build script is served when its compile uses only what
/// the script set through Cargo (`--cfg` in argv, `rustc-env` keyed with its
/// value) and never reads `OUT_DIR`; one that includes generated source from
/// `OUT_DIR` executes every time and is never published.
#[test]
#[allow(clippy::too_many_lines)]
fn build_script_packages_serve_only_when_out_dir_is_never_read() {
    let dir = tempfile::Builder::new()
        .prefix("rs")
        .tempdir_in("/tmp")
        .unwrap();
    let world = World {
        root: dir.path().to_path_buf(),
        socket: dir.path().join("d.sock"),
        rustc: real_rustc(),
        git_checkout: None,
    };
    world.write_package(
        "leaf",
        "#[cfg(fast)]\npub fn speed() -> &'static str { env!(\"FLAVOR\") }\n\
         #[cfg(not(fast))]\npub fn speed() -> &'static str { \"slow\" }\n",
    );
    world.write_package(
        "mid",
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
    );
    let daemon = Daemon::start(&world.root, &world.socket);
    let script = "cargo:rerun-if-changed=build.rs\ncargo:rustc-cfg=fast\n\
                  cargo:rustc-env=FLAVOR=turbo\n";
    let run = |name: &str, worktree: &str, stock: bool| -> (Output, PathBuf, PathBuf) {
        let root = world.root.join(worktree);
        let out = world.out_dir(worktree);
        let build_out = build_script_record(&root, name, script);
        std::fs::write(
            build_out.join("generated.rs"),
            "pub const GENERATED: u32 = 7;\n",
        )
        .unwrap();
        let mut args = world.cargo_args(name, &out, &[]);
        args.extend(["--cfg".to_owned(), "fast".to_owned()]);
        let mut env = world.env(name);
        env.push(("OUT_DIR".into(), build_out.display().to_string()));
        env.push(("FLAVOR".into(), "turbo".into()));
        let mut command = if stock {
            Command::new(&world.rustc)
        } else {
            let mut command = Command::new(wrap());
            command.arg(&world.rustc);
            command
        };
        let output = command
            .args(args)
            .current_dir(world.package(name))
            .env_clear()
            .envs(env)
            .output()
            .expect("run compiler");
        (output, out, build_out)
    };
    let build = |name: &str, worktree: &str| -> Vec<String> {
        let mark = daemon.decisions().len();
        let (output, _, _) = run(name, worktree, false);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{name} {worktree}: {output:?}"
        );
        trail(&daemon, mark)
    };

    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let trail = build("leaf", "wt-a");
        if trail.contains(&"committed".to_owned()) {
            assert_eq!(trail, ["execute", "committed"]);
            break;
        }
        assert!(
            trail.iter().all(|step| step == "toolchain-warming"),
            "unexpected decisions while warming: {trail:?}"
        );
        assert!(Instant::now() < deadline, "toolchain probe never warmed");
        std::thread::sleep(Duration::from_millis(250));
    }
    for worktree in ["wt-b", "wt-c"] {
        assert_eq!(
            build("leaf", worktree),
            ["execute", "verified"],
            "{worktree}"
        );
    }
    assert_eq!(build("leaf", "wt-d"), ["hit", "served"]);
    let (stock, stock_out, _) = run("leaf", "stock", true);
    assert_eq!(stock.status.code(), Some(0), "{stock:?}");
    for file in &cargo_outputs("leaf")[..2] {
        assert_eq!(
            std::fs::read(world.root.join("wt-d/target/debug/deps").join(file)).unwrap(),
            std::fs::read(stock_out.join(file)).unwrap(),
            "served {file} differs from stock"
        );
    }

    // Generated source from OUT_DIR. The relocatable attempt compiles
    // correctly but cannot publish, and marks the package an OUT_DIR reader;
    // its next request is keyed in exact mode (this worktree's OUT_DIR path
    // and the generated tree) and commits under that different key.
    let execute_key = |mark: usize| {
        daemon.decisions()[mark..]
            .iter()
            .find(|decision| decision["decision"] == "execute")
            .and_then(|decision| decision["key"].as_str().map(str::to_owned))
            .unwrap()
    };
    let mark = daemon.decisions().len();
    let (output, _, _) = run("mid", "wt-a", false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        trail(&daemon, mark),
        ["execute", "out-dir-reader", "not-published"]
    );
    // The closure check names the read below OUT_DIR (or the tracked
    // OUT_DIR read itself), whichever dep-info lists first.
    assert!(daemon.decisions()[mark..].iter().any(|decision| {
        decision["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("out/generated.rs") || detail.contains("OUT_DIR"))
    }));
    let relocatable = execute_key(mark);
    let mark = daemon.decisions().len();
    let (output, _, _) = run("mid", "wt-b", false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(trail(&daemon, mark), ["execute", "committed"]);
    assert_ne!(
        execute_key(mark),
        relocatable,
        "exact mode keys differently"
    );
}
