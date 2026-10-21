//! Real managed Cargo roots; requires an explicitly delegated cgroup-v2 root.
//! Ordinary filesystem fixtures are never treated as containment evidence.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Runs {
    root: PathBuf,
    root_identity: (u64, u64),
    children: Vec<Child>,
}

impl Runs {
    fn new() -> Self {
        let parent = std::env::var_os("RABS_TEST_ROOT_CGROUP")
            .map(PathBuf::from)
            .expect("set RABS_TEST_ROOT_CGROUP to an explicit writable delegation");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!("rabs-root-fixture-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).expect("create this fixture's exclusive cgroup delegation");
        let metadata = fs::symlink_metadata(&root).unwrap();
        Self {
            root,
            root_identity: (metadata.dev(), metadata.ino()),
            children: Vec::new(),
        }
    }

    fn start(&mut self, budget: &Path, workspace: &Path, args: &[&str]) -> usize {
        let child = Command::new(env!("CARGO_BIN_EXE_rabs-cargo-root"))
            .arg("--")
            .arg(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(args)
            .current_dir(workspace)
            .env("CARGO_RABS_ROOT_BUDGET_DIR", budget)
            .env("CARGO_RABS_ROOT_CAPACITY", "1")
            .env("CARGO_RABS_ROOT_CGROUP", &self.root)
            .env_remove("CARGO_RABS_ROOT_ACTIVE")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env("CARGO_TARGET_DIR", workspace.join("target"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        self.children.push(child);
        self.children.len() - 1
    }

    fn groups(&self, index: usize) -> Vec<PathBuf> {
        let metadata = fs::symlink_metadata(&self.root).unwrap();
        assert!(metadata.is_dir());
        assert_eq!((metadata.dev(), metadata.ino()), self.root_identity);
        let prefix = format!("rabs-root-{}-", self.children[index].id());
        fs::read_dir(&self.root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect()
    }

    fn wait(&mut self, index: usize) -> std::process::ExitStatus {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.children[index].try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < until, "managed Cargo did not finish");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Runs {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        // The private subgroup was created exclusively for this fixture. Never
        // rediscover ownership from a dead helper's potentially recycled PID.
        if !fs::symlink_metadata(&self.root).is_ok_and(|metadata| {
            metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.root_identity
        }) {
            return;
        }
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.filter_map(Result::ok) {
                if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                let group = entry.path();
                let _ = fs::write(group.join("cgroup.kill"), b"1\n");
                let until = Instant::now() + Duration::from_secs(5);
                while fs::read_to_string(group.join("cgroup.events"))
                    .is_ok_and(|text| text.lines().any(|line| line == "populated 1"))
                    && Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                let _ = fs::remove_dir(group);
            }
        }
        let _ = fs::remove_dir(&self.root);
    }
}

fn workspace(root: &Path) {
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='root-fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
    )
    .unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(
        root.join("build.rs"),
        r#"
use std::{fs, process::{Command, Stdio}, thread, time::Duration};
fn main() {
    let root = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let detached = Command::new("setsid").args(["sh", "-c", "sleep 60"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    fs::write(format!("{root}/descendant"), detached.id().to_string()).unwrap();
    fs::write(format!("{root}/ready"), b"ready").unwrap();
    while !std::path::Path::new(&format!("{root}/release")).exists() {
        thread::sleep(Duration::from_millis(20));
    }
}
"#,
    )
    .unwrap();
}

fn ready(runs: &mut Runs, index: usize, root: &Path) {
    let until = Instant::now() + Duration::from_secs(30);
    while !root.join("ready").exists() {
        assert!(
            runs.children[index].try_wait().unwrap().is_none(),
            "Cargo exited before fixture readiness"
        );
        assert!(Instant::now() < until, "Cargo fixture did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires a real writable cgroup-v2 delegation, Cargo, and setsid"]
fn cargo_roots_wait_for_capacity_until_setsid_descendants_are_gone() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    workspace(root);
    let budget = root.join("budget");
    let mut runs = Runs::new();
    let first = runs.start(&budget, root, &["build", "--offline"]);
    ready(&mut runs, first, root);
    let first_group = runs
        .groups(first)
        .pop()
        .expect("first Cargo owns its cgroup");
    let second = runs.start(&budget, root, &["--version"]);
    std::thread::sleep(Duration::from_millis(250));
    assert!(
        runs.children[second].try_wait().unwrap().is_none(),
        "second root bypassed held credit"
    );
    fs::write(root.join("release"), b"release").unwrap();
    assert!(runs.wait(first).success());
    assert!(runs.wait(second).success());
    assert!(root.join("target/debug/root-fixture").is_file());
    assert!(
        !first_group.exists(),
        "setsid descendant kept the cgroup populated"
    );
}

#[test]
#[ignore = "requires a real writable cgroup-v2 delegation, Cargo, and setsid"]
fn killed_owner_keeps_root_credit_quarantined_even_after_tree_cleanup() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    workspace(root);
    let budget = root.join("budget");
    let mut runs = Runs::new();
    let first = runs.start(&budget, root, &["build", "--offline"]);
    ready(&mut runs, first, root);
    let group = runs
        .groups(first)
        .pop()
        .expect("first Cargo owns its cgroup");
    runs.children[first].kill().unwrap();
    assert!(!runs.wait(first).success());
    assert!(
        fs::read_to_string(group.join("cgroup.events"))
            .unwrap()
            .lines()
            .any(|line| line == "populated 1")
    );
    let refused = runs.start(&budget, root, &["--version"]);
    assert_eq!(runs.wait(refused).code(), Some(2));
    fs::write(group.join("cgroup.kill"), b"1\n").unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while fs::read_to_string(group.join("cgroup.events"))
        .unwrap()
        .lines()
        .any(|line| line == "populated 1")
    {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(20));
    }
    let still_refused = runs.start(&budget, root, &["--version"]);
    assert_eq!(
        runs.wait(still_refused).code(),
        Some(2),
        "new owner manufactured release authority"
    );
}
