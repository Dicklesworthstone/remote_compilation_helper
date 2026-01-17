use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

pub struct TestProject {
    pub dir: TempDir,
    pub cargo_toml: PathBuf,
    pub src_main: PathBuf,
}

impl TestProject {
    pub fn new() -> Self {
        crate::test_log!("FIXTURE: Creating test Rust project");

        let dir = TempDir::new().expect("Failed to create temp dir");
        let cargo_toml = dir.path().join("Cargo.toml");
        let src_dir = dir.path().join("src");
        let src_main = src_dir.join("main.rs");

        fs::create_dir_all(&src_dir).expect("Failed to create src dir");
        fs::write(
            &cargo_toml,
            r#"[package]
name = "rch_test_project"
version = "0.1.0"
edition = "2024"

[dependencies]
"#,
        )
        .expect("Failed to write Cargo.toml");
        fs::write(&src_main, "fn main() { println!(\"ok\"); }\n")
            .expect("Failed to write src/main.rs");

        Self {
            dir,
            cargo_toml,
            src_main,
        }
    }
}
