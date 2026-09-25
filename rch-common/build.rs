use std::env;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_COMMIT_ENV_VARS: &[&str] = &[
    "RCH_GIT_COMMIT",
    "VERGEN_GIT_SHA",
    "GIT_COMMIT",
    "GITHUB_SHA",
];

fn main() {
    for key in BUILD_COMMIT_ENV_VARS {
        println!("cargo:rerun-if-env-changed={key}");
    }
    println!("cargo:rerun-if-env-changed=RCH_BUILD_SOURCE");

    register_git_rerun_paths();

    let source = env::var_os("RCH_BUILD_SOURCE");
    let commit = env_commit().or_else(|| match source.as_ref() {
        Some(source) => source
            .to_str()
            .map(str::trim)
            .filter(|source| is_build_source_stamp(source))
            .map(str::to_owned),
        None => git_head_commit(),
    });
    // Blank every alias rustc would otherwise inherit from the ambient
    // environment, so `build_commit()` only ever sees the value validated
    // here. Without this, an alias this script rejected (e.g.
    // `GIT_COMMIT=not-a-commit` in a tree with no `.git`) leaked through to
    // `--version` unchanged (issue #76).
    for key in BUILD_COMMIT_ENV_VARS {
        if *key == "RCH_GIT_COMMIT" && commit.is_some() {
            continue;
        }
        println!("cargo:rustc-env={key}=");
    }
    if let Some(commit) = commit {
        println!("cargo:rustc-env=RCH_GIT_COMMIT={commit}");
    }
}

fn is_build_source_stamp(value: &str) -> bool {
    is_commit_hash(value)
        || value.strip_suffix("-dirty").is_some_and(is_commit_hash)
        || value
            .split_once("-overlay-")
            .is_some_and(|(commit, fingerprint)| {
                is_commit_hash(commit)
                    && fingerprint.len() == 64
                    && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}

fn env_commit() -> Option<String> {
    BUILD_COMMIT_ENV_VARS.iter().find_map(|key| {
        env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| is_commit_hash(value))
    })
}

fn git_head_commit() -> Option<String> {
    let manifest_dir = manifest_dir()?;
    let output = Command::new("git")
        .arg("-C")
        .arg(manifest_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let commit = stdout.trim().to_string();
    is_commit_hash(&commit).then_some(commit)
}

fn register_git_rerun_paths() {
    let Some(manifest_dir) = manifest_dir() else {
        return;
    };
    let workspace_root = manifest_dir.parent().unwrap_or(&manifest_dir);
    let dot_git = workspace_root.join(".git");

    emit_rerun_if_exists(&dot_git);

    if dot_git.is_dir() {
        register_git_head_paths(&dot_git);
        return;
    }

    let Ok(dot_git_contents) = std::fs::read_to_string(&dot_git) else {
        return;
    };
    let Some(gitdir) = dot_git_contents.trim().strip_prefix("gitdir: ") else {
        return;
    };

    let git_dir = PathBuf::from(gitdir);
    let git_dir = if git_dir.is_absolute() {
        git_dir
    } else {
        workspace_root.join(git_dir)
    };
    register_git_head_paths(&git_dir);
}

fn register_git_head_paths(git_dir: &Path) {
    let head_path = git_dir.join("HEAD");
    emit_rerun_if_exists(&head_path);

    let Ok(head_contents) = std::fs::read_to_string(&head_path) else {
        return;
    };
    let Some(ref_path) = head_contents.trim().strip_prefix("ref: ") else {
        return;
    };
    let Some(git_ref) = clean_git_ref_path(ref_path) else {
        return;
    };
    emit_rerun_if_exists(&git_dir.join(git_ref));
}

fn emit_rerun_if_exists(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn manifest_dir() -> Option<PathBuf> {
    env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)
}

fn clean_git_ref_path(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if raw.is_empty() || path.is_absolute() {
        return None;
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(path.to_path_buf())
}

fn is_commit_hash(value: &str) -> bool {
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
