//! Named Cargo binary/example retrieval without unrelated pooled build outputs.
//!
//! This is an optimization of the existing retrieval policy, not a proof of
//! output completeness. Only literal `cargo build --bin/--example` selections
//! narrow retrieval. Unknown flags, shell expansion, other target kinds,
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
    let mut examples = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut profile = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let (flag, inline) = arg.split_once('=').map_or((arg, None), |(k, v)| (k, Some(v)));
        match flag {
            "--bin" | "--example" => {
                let name = inline.or_else(|| iter.next())?;
                if !component(name) {
                    return None;
                }
                if flag == "--bin" {
                    bins.insert(name);
                } else {
                    examples.insert(name);
                }
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
            // Includes --bins/--examples/--lib/--all-targets and test selectors,
            // --timings, --config, -Z, output-dir overrides and `--` passthrough.
            _ => return None,
        }
    }
    if bins.is_empty() && examples.is_empty() {
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
            add_named_output(&mut selected, &root, name);
        }
        let example_root = format!("{root}/examples");
        for name in &examples {
            // Examples may be bin, rlib, staticlib, cdylib or dylib targets.
            // Keep both executable spelling and normalized crate/library names
            // rather than assuming that every example has a main function.
            let crate_name = name.replace('-', "_");
            for stem in [(*name).to_owned(), crate_name.clone(), format!("lib{crate_name}")] {
                add_named_output(&mut selected, &example_root, &stem);
            }
        }
        // A linked binary may still need dynamic dependencies. Preserve these
        // and split-debug data, but not dependency rlibs/rmeta/object caches or
        // other hashed executables from the shared target pool.
        let mut runtime_dirs = vec![root.clone(), format!("{root}/deps")];
        if !examples.is_empty() {
            runtime_dirs.push(example_root);
        }
        for directory in runtime_dirs {
            for suffix in ["so", "so.*", "dylib", "dll", "pdb", "dwo", "dwp"] {
                selected.insert(format!("{directory}/*.{suffix}"));
            }
            selected.insert(format!("{directory}/*.dSYM/**"));
        }
    }
    Some(selected.into_iter().collect())
}

/// Platform extensions and sidecar bundles, but not unrelated name prefixes.
fn add_named_output(selected: &mut BTreeSet<String>, directory: &str, name: &str) {
    selected.insert(format!("{directory}/{name}"));
    selected.insert(format!("{directory}/{name}.*"));
    selected.insert(format!("{directory}/{name}.*/**"));
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
    if !matches!(words.get(index).copied(), Some("build" | "b")) {
        return None;
    }
    Some(words[index + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::super::{get_custom_target_artifact_patterns, get_project_artifact_patterns};
    use super::*;

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

    #[test]
    fn named_examples_preserve_executable_and_library_forms_in_mixed_requests() {
        for command in [
            "cargo build --example demo-lib --profile lean",
            "cargo build --bin app --example=demo-lib --profile=lean",
        ] {
            let selected = select(command).unwrap();
            for expected in [
                "target/lean/examples/demo-lib",
                "target/lean/examples/demo_lib.*",
                "target/lean/examples/libdemo_lib.*",
                "target/*/lean/examples/libdemo_lib.*",
                "target/lean/examples/demo-lib.*/**",
                "target/lean/deps/*.so",
            ] {
                assert!(selected.iter().any(|pattern| pattern == expected), "{expected}");
            }
            assert!(!selected.iter().any(|p| p.ends_with("examples/**")));
            let kind = Some(CompilationKind::CargoBuild);
            assert!(get_project_artifact_patterns(kind, Some(command), true).is_empty());
            let custom = get_custom_target_artifact_patterns(kind, Some(command));
            assert!(custom.contains(&"lean/examples/libdemo_lib.*".to_owned()));
        }
        let mixed = select("cargo build --bin app --example demo").unwrap();
        assert!(mixed.contains(&"target/debug/app".to_owned()));
        assert!(mixed.contains(&"target/debug/examples/demo".to_owned()));
        for command in [
            "cargo build --example demo --examples",
            "cargo build --example demo --lib",
            "cargo build --example demo --test integration",
            "cargo build --example ../demo",
            "cargo build --example demo --bin app --all-targets",
        ] {
            assert!(select(command).is_none(), "{command}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_rsync_keeps_outputs_sidecars_and_runtime_libraries_not_pool_residue() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        for (forwarded, example) in [(false, false), (true, false), (false, true), (true, true)] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("worker");
            let destination = root.path().join("local");
            let prefix = if forwarded { "lean" } else { "target/lean" };
            let mut keep = vec![
                "app", "app.exe", "app.pdb", "app.dSYM/Contents/Resources/DWARF/app",
                "deps/libneeded.so", "deps/libneeded.so.1", "deps/libneeded.dylib",
                "deps/needed.dll", "deps/split.dwo",
            ];
            if example {
                keep.extend([
                    "examples/demo-lib", "examples/demo_lib.exe", "examples/libdemo_lib.a",
                    "examples/demo_lib.lib", "examples/libdemo_lib.rlib",
                    "examples/libdemo_lib.so", "examples/demo-lib.dSYM/Contents/Info.plist",
                ]);
            }
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
            let command = Some(if example {
                "cargo build --bin app --example demo-lib --profile lean"
            } else {
                "cargo build --bin app --profile lean"
            });
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
                for relative in &keep {
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

    #[cfg(unix)]
    #[tokio::test]
    async fn real_cargo_selected_bins_and_library_examples_round_trip() {
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::process::Command;

        for forwarded in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let local = root.path().join("local");
            std::fs::create_dir_all(source.join("src")).unwrap();
            std::fs::create_dir_all(source.join("examples")).unwrap();
            std::fs::create_dir_all(&local).unwrap();
            std::fs::write(source.join("Cargo.toml"), concat!(
                "[package]\nname = \"rch_selected_fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
                "[workspace]\n",
                "[[bin]]\nname = \"app\"\npath = \"src/main.rs\"\n",
                "[[example]]\nname = \"demo\"\npath = \"examples/demo.rs\"\n",
                "[[example]]\nname = \"demo-lib\"\npath = \"examples/library.rs\"\ncrate-type = [\"staticlib\"]\n",
                "[profile.lean]\ninherits = \"dev\"\ndebug = 0\n",
            )).unwrap();
            std::fs::write(source.join("src/main.rs"), "fn main() { println!(\"selected app\"); }\n").unwrap();
            std::fs::write(source.join("examples/demo.rs"), "fn main() { println!(\"selected example\"); }\n").unwrap();
            std::fs::write(source.join("examples/library.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
            let remote_target = if forwarded { root.path().join("worker-target") } else { source.join("target") };
            let command_text = "cargo build --bin app --example demo --example demo-lib --profile lean --offline --jobs=1";
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut compile = Command::new(cargo);
            compile.current_dir(&source).args(command_text.split_ascii_whitespace().skip(1))
                .arg("--message-format=json")
                .env("CARGO_HOME", root.path().join("cargo-home"))
                .env("CARGO_TARGET_DIR", &remote_target)
                .env_remove("RUSTC_WRAPPER").env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("RUSTFLAGS").env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_TARGET").env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_BUILD_BUILD_DIR").env_remove("CARGO_MAKEFLAGS").env_remove("MAKEFLAGS")
                .stdin(Stdio::null()).kill_on_drop(true);
            let built = tokio::time::timeout(Duration::from_secs(90), compile.output())
                .await.expect("owned Cargo fixture timed out").expect("Cargo is required");
            assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
            let artifacts: Vec<serde_json::Value> = String::from_utf8(built.stdout).unwrap()
                .lines().filter_map(|line| serde_json::from_str(line).ok())
                .filter(|message: &serde_json::Value| message["reason"] == "compiler-artifact")
                .collect();
            assert_eq!(artifacts.len(), 3, "fixture must compile one bin and two examples");
            let files: Vec<std::path::PathBuf> = artifacts.iter()
                .flat_map(|message| message["filenames"].as_array().unwrap())
                .map(|filename| filename.as_str().unwrap().into()).collect();
            assert!(files.iter().any(|p| p.file_name().unwrap() == "libdemo_lib.a"));
            let remote_basis = if forwarded { &remote_target } else { &source };
            for path in &files {
                let destination = local.join(path.strip_prefix(remote_basis).unwrap());
                std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                std::fs::write(destination, b"stale artifact\n").unwrap();
            }
            std::fs::write(remote_target.join("lean/not_requested"), b"pooled residue\n").unwrap();
            let kind = Some(CompilationKind::CargoBuild);
            let selected = if forwarded {
                get_custom_target_artifact_patterns(kind, Some(command_text))
            } else {
                get_project_artifact_patterns(kind, Some(command_text), false)
            };
            assert!(!selected.iter().any(|p| p.ends_with("lean/**")));
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
            copy.arg("--exclude=*").arg(format!("{}/", remote_basis.display()))
                .arg(format!("{}/", local.display())).stdin(Stdio::null()).kill_on_drop(true);
            let copied = tokio::time::timeout(Duration::from_secs(15), copy.output())
                .await.expect("owned rsync fixture timed out").expect("rsync is required");
            assert!(copied.status.success(), "{copied:?}");
            for path in files {
                let destination = local.join(path.strip_prefix(remote_basis).unwrap());
                assert_eq!(std::fs::read(&destination).unwrap(), std::fs::read(&path).unwrap(), "{}", path.display());
            }
            let residue = remote_target.join("lean/not_requested");
            assert!(!local.join(residue.strip_prefix(remote_basis).unwrap()).exists());
            for artifact in artifacts {
                if let Some(executable) = artifact["executable"].as_str() {
                    let executable = local.join(Path::new(executable).strip_prefix(remote_basis).unwrap());
                    let mut run = Command::new(executable);
                    run.stdin(Stdio::null()).kill_on_drop(true);
                    let ran = tokio::time::timeout(Duration::from_secs(10), run.output())
                        .await.expect("returned executable timed out").unwrap();
                    assert!(ran.status.success(), "{ran:?}");
                    assert!(String::from_utf8_lossy(&ran.stdout).contains("selected"));
                }
            }
        }
    }
}
