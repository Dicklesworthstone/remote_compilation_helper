//! Named Cargo binary retrieval without copying unrelated pooled build outputs.
//!
//! This is an optimization of the existing retrieval policy, not a proof of
//! output completeness. Only literal, understood `cargo build --bin` commands
//! narrow the selection. Unknown flags, shell expansion, mixed target kinds,
//! response files and custom target specifications retain the broad policy.

use rch_common::CompilationKind;
use std::collections::BTreeSet;
use std::path::Path;

/// Return project-root patterns; the caller rebases them for custom target dirs.
pub(super) fn patterns(
    kind: Option<CompilationKind>,
    command: Option<&str>,
) -> Option<Vec<String>> {
    if kind != Some(CompilationKind::CargoBuild) {
        return None;
    }
    let args = build_arguments(command?)?;
    let mut bins = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut profile = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let (flag, inline) = arg.split_once('=').map_or((arg, None), |(k, v)| (k, Some(v)));
        match flag {
            "--bin" => {
                let name = inline.or_else(|| iter.next())?;
                if !component(name) {
                    return None;
                }
                bins.insert(name);
            }
            "--target" => {
                let target = inline.or_else(|| iter.next())?;
                // Cargo substitutes host-tuple at runtime; it is not a directory.
                if !component(target) || target == "host-tuple" {
                    return None;
                }
                targets.insert(target);
            }
            "--profile" => {
                let value = inline.or_else(|| iter.next())?;
                let dir = match value {
                    "dev" | "test" => "debug",
                    "release" | "bench" => "release",
                    value if component(value) => value,
                    _ => return None,
                };
                set_profile(&mut profile, dir)?;
            }
            "--release" | "-r" if inline.is_none() => {
                set_profile(&mut profile, "release")?;
            }
            "--package" | "-p" | "--exclude" | "--jobs" | "-j" | "--features" | "-F"
            | "--color" | "--message-format" | "--manifest-path" | "--target-dir" => {
                // Consume opaque option values exactly once, never as selectors.
                let value = inline.or_else(|| iter.next())?;
                if value.is_empty() || value.starts_with('-') {
                    return None;
                }
            }
            "--workspace" | "--all" | "--all-features" | "--no-default-features"
            | "--locked" | "--frozen" | "--offline" | "--keep-going" | "--verbose"
            | "--quiet" | "-v" | "-vv" | "-q" if inline.is_none() => {}
            _ if inline.is_none()
                && ["-p", "-j", "-F"].iter().any(|prefix| {
                    arg.starts_with(*prefix) && arg.len() > prefix.len()
                }) => {}
            // Includes --bins/--lib/--all-targets, test/example selectors,
            // --timings, --config, -Z, output-dir overrides and `--` passthrough.
            _ => return None,
        }
    }
    if bins.is_empty() {
        return None;
    }
    let profile = profile.unwrap_or("debug");
    let roots: Vec<String> = if targets.is_empty() {
        // Configuration/environment can choose a target even without --target.
        vec![format!("target/{profile}"), format!("target/*/{profile}")]
    } else {
        targets
            .into_iter()
            .map(|target| format!("target/{target}/{profile}"))
            .collect()
    };
    let mut selected = BTreeSet::new();
    for root in roots {
        for name in &bins {
            selected.insert(format!("{root}/{name}"));
            // Platform suffixes and adjacent sidecars, without matching a
            // different binary merely because it has the same name prefix.
            selected.insert(format!("{root}/{name}.*"));
            selected.insert(format!("{root}/{name}.*/**"));
        }
        // A linked binary may still need dynamic dependencies. Preserve these
        // and split-debug data, but not dependency rlibs/rmeta/object caches or
        // other hashed executables from the shared target pool.
        for directory in [root.clone(), format!("{root}/deps")] {
            for suffix in ["so", "so.*", "dylib", "dll", "pdb", "dwo", "dwp"] {
                selected.insert(format!("{directory}/*.{suffix}"));
            }
            selected.insert(format!("{directory}/*.dSYM/**"));
        }
    }
    Some(selected.into_iter().collect())
}

fn set_profile<'a>(profile: &mut Option<&'a str>, value: &'a str) -> Option<()> {
    if profile.is_some_and(|previous| previous != value) {
        return None;
    }
    *profile = Some(value);
    Some(())
}

/// No path separators, glob operators, traversal, suffixes or filter syntax.
fn component(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Deliberately a bounded literal subset, not a second shell parser. Quoted or
/// expanded commands are valid elsewhere but cannot authorize this narrowing.
fn build_arguments(command: &str) -> Option<Vec<&str>> {
    if command.len() > 65_536
        || !command.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'\t' | b'_' | b'-' | b'.' | b'/' | b'=' | b'+' | b':' | b',')
        })
    {
        return None;
    }
    let words: Vec<_> = command.split_ascii_whitespace().collect();
    if words.len() > 4096 {
        return None;
    }
    let mut index = 0;
    loop {
        while words.get(index).is_some_and(|word| {
            word.split_once('=')
                .is_some_and(|(key, _)| rch_common::ssh_utils::is_valid_env_key(key))
        }) {
            index += 1;
        }
        let executable = Path::new(words.get(index)?).file_name()?.to_str()?;
        match executable.strip_suffix(".exe").unwrap_or(executable) {
            "cargo" => break,
            "env" => {
                index += 1;
                while let Some(word) = words.get(index) {
                    match *word {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-i" | "--ignore-environment" => index += 1,
                        "-u" | "--unset" => {
                            let key = words.get(index + 1)?;
                            if !rch_common::ssh_utils::is_valid_env_key(key) {
                                return None;
                            }
                            index += 2;
                        }
                        _ if word.starts_with("--unset=") => {
                            if !rch_common::ssh_utils::is_valid_env_key(&word[8..]) {
                                return None;
                            }
                            index += 1;
                        }
                        _ if word.starts_with('-') => return None,
                        _ => break,
                    }
                }
            }
            "rustup" => {
                if words.get(index + 1) != Some(&"run") {
                    return None;
                }
                let channel = words.get(index + 2)?;
                if channel.is_empty() || channel.starts_with('-') {
                    return None;
                }
                index += 3;
            }
            _ => return None,
        }
    }
    index += 1;
    if words.get(index).is_some_and(|word| word.starts_with('+')) {
        index += 1;
    }
    if !matches!(words.get(index), Some(&"build" | &"b")) {
        return None;
    }
    Some(words[index + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{get_custom_target_artifact_patterns, get_project_artifact_patterns};

    fn select(command: &str) -> Option<Vec<String>> {
        patterns(Some(CompilationKind::CargoBuild), Some(command))
    }

    #[test]
    fn explicit_bins_select_only_the_requested_profile_and_names() {
        let selected = select("cargo build --release --bin rch --bin=rchd --bin rch").unwrap();
        for expected in [
            "target/release/rch", "target/release/rchd", "target/*/release/rch",
            "target/release/rch.*", "target/release/rch.*/**",
            "target/release/deps/*.so", "target/release/deps/*.dwo",
        ] {
            assert!(selected.iter().any(|pattern| pattern == expected), "{expected}");
        }
        assert!(!selected.iter().any(|pattern| pattern.contains("debug")));
        assert!(!selected.iter().any(|pattern| pattern.ends_with("release/**")));
        assert!(!selected.iter().any(|pattern| pattern.ends_with("deps/**")));
        assert_eq!(selected.iter().filter(|p| *p == "target/release/rch").count(), 1);
    }

    #[test]
    fn wrappers_profiles_targets_and_opaque_arguments_are_resolved() {
        for command in [
            "CARGO_TARGET_DIR=/tmp/out cargo +nightly build --bin app --profile small --target x86_64-unknown-linux-gnu",
            "env -u RUSTFLAGS -- rustup run nightly /usr/bin/cargo b --bin=app --profile=small --target=x86_64-unknown-linux-gnu",
        ] {
            let selected = select(command).unwrap();
            assert!(selected.contains(&"target/x86_64-unknown-linux-gnu/small/app".into()));
            assert!(selected.iter().all(|p| p.starts_with("target/x86_64-unknown-linux-gnu/small/")));
        }
        assert!(select("cargo build --package --bin app").is_none());
        assert!(select("cargo build --features=--bin=decoy").is_none());
        assert!(select("cargo build --bin app --profile dev").unwrap().contains(&"target/debug/app".into()));
        assert!(select("cargo build --bin app --target a --target b").unwrap().contains(&"target/b/debug/app".into()));
    }

    #[test]
    fn ambiguous_or_additional_outputs_retain_the_broad_policy() {
        for command in [
            "cargo build", "cargo build --bins", "cargo build --bin app --lib",
            "cargo build --bin app --examples", "cargo build --bin app --all-targets",
            "cargo build --bin app --timings", "cargo build --bin app --config foo.toml",
            "cargo build --bin app -Z unstable-options", "cargo build --bin app --out-dir out",
            "cargo test --no-run --bin app", "cargo rustc --bin app -- --emit asm",
            "cargo build --bin app --target custom.json", "cargo build --bin app --target host-tuple",
            "cargo build --bin app --profile ../source", "cargo build --bin ../app",
            "cargo build --bin app --release --profile dev", "cargo build --bin app --profile",
            "cargo build --bin app --unknown", "cargo build --bin app --",
            "cargo build --bin 'app*'", "cargo build --bin $APP", "cargo build --bin app; echo x",
            "env -C other cargo build --bin app", "sh -c cargo build --bin app",
        ] {
            assert!(select(command).is_none(), "narrowed ambiguous command: {command}");
        }
        assert!(patterns(Some(CompilationKind::CargoDoc), Some("cargo build --bin app")).is_none());
    }

    #[test]
    fn both_live_retrieval_bases_use_the_selection() {
        let kind = Some(CompilationKind::CargoBuild);
        let command = Some("cargo build --bin app --profile lean");
        let project = get_project_artifact_patterns(kind, command, false);
        assert_eq!(project, patterns(kind, command).unwrap());
        assert!(get_project_artifact_patterns(kind, command, true).is_empty());
        let custom = get_custom_target_artifact_patterns(kind, command);
        for pattern in &project {
            assert!(custom.contains(&pattern.strip_prefix("target/").unwrap().to_owned()));
        }
        assert!(!custom.iter().any(|p| p == "lean/**" || p == "debug/**"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_rsync_keeps_outputs_sidecars_and_runtime_libraries_not_pool_residue() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        for forwarded in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("worker");
            let destination = root.path().join("local");
            let prefix = if forwarded { "lean" } else { "target/lean" };
            let keep = [
                "app", "app.exe", "app.pdb", "app.dSYM/Contents/Resources/DWARF/app",
                "deps/libneeded.so", "deps/libneeded.so.1", "deps/libneeded.dylib",
                "deps/needed.dll", "deps/split.dwo",
            ];
            let omit = [
                "other", "app-helper", "deps/app-deadbeef", "deps/libhuge.rlib",
                "incremental/state", ".fingerprint/state", "build/state", "examples/other",
            ];
            for relative in keep.iter().chain(omit.iter()) {
                let path = source.join(prefix).join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, format!("fresh {relative}\n")).unwrap();
            }
            std::fs::create_dir_all(destination.join(prefix)).unwrap();
            std::fs::write(destination.join(prefix).join("app"), b"stale executable\n").unwrap();
            std::fs::write(destination.join("source.rs"), b"local source sentinel\n").unwrap();
            std::fs::write(source.join("source.rs"), b"foreign source\n").unwrap();
            let kind = Some(CompilationKind::CargoBuild);
            let command = Some("cargo build --bin app --profile lean");
            let selected = if forwarded {
                get_custom_target_artifact_patterns(kind, command)
            } else {
                get_project_artifact_patterns(kind, command, false)
            };
            for _ in 0..2 {
                let mut copy = Command::new("rsync");
                copy.args(["-a", "--checksum", "--safe-links", "--prune-empty-dirs"]);
                for rule in &selected {
                    if let Some(exclude) = rule.strip_prefix("- ") {
                        copy.arg(format!("--exclude={exclude}"));
                    }
                }
                copy.arg("--include=*/");
                for rule in &selected {
                    if !rule.starts_with("- ") {
                        copy.arg(format!("--include=/{rule}"));
                    }
                }
                copy.arg("--exclude=*").arg(format!("{}/", source.display()))
                    .arg(format!("{}/", destination.display())).stdin(Stdio::null()).kill_on_drop(true);
                let copied = tokio::time::timeout(Duration::from_secs(10), copy.output())
                    .await.expect("owned rsync fixture timed out").expect("rsync is required");
                assert!(copied.status.success(), "{copied:?}");
                for relative in keep {
                    assert_eq!(std::fs::read(destination.join(prefix).join(relative)).unwrap(),
                        std::fs::read(source.join(prefix).join(relative)).unwrap(), "{relative}");
                }
                for relative in omit {
                    assert!(!destination.join(prefix).join(relative).exists(), "copied {relative}");
                }
                assert_eq!(std::fs::read(destination.join("source.rs")).unwrap(), b"local source sentinel\n");
            }
        }
    }
}
