//! Execute the production in-namespace trampoline without requiring userns.
//! Only the namespace path lookup is substituted with the physical HOME path;
//! the generated command, exact environment, FIFO, descriptors, managed process
//! group and actual make/cc/ar are real. jobserver_bridge_linux separately
//! exercises the complete worker TCP session on namespace-capable hosts.

use super::JobserverBridge;
use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use rabs_sandbox::canonical_namespace::{CanonicalNamespaceSpec, HostIsolationSupport};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn builder_support() -> HostIsolationSupport {
    HostIsolationSupport {
        bubblewrap: Some("argv-construction-only".into()),
        unprivileged_userns: true,
        overlayfs: false,
        cgroup_v2: false,
        landlock: false,
    }
}

fn environment(bridge: &JobserverBridge) -> Vec<(String, String)> {
    let mut env = vec![("PATH".into(), "/usr/bin:/bin".into())];
    JobserverBridge::apply(&mut env, bridge);
    env
}

fn run(
    bridge: &mut JobserverBridge,
    cwd: &Path,
    env: Vec<(String, String)>,
    program: &str,
    args: &[String],
) -> Output {
    // This is the one fixture substitution: the same kernel FIFO is reachable
    // without mounting HOME. Never claim this proves namespace enforcement.
    bridge.visible_path = bridge.host_path.to_str().unwrap().to_owned();
    let mut spec = CanonicalNamespaceSpec::new();
    spec.env = env;
    let launch = bridge
        .canonical_launch(&spec, &builder_support(), program, args)
        .unwrap();
    let delimiter = launch.argv.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(launch.argv[delimiter + 1], "/bin/sh");
    assert!(
        launch.argv[..delimiter]
            .iter()
            .any(|arg| arg == "--clearenv")
    );
    assert!(launch.argv[..delimiter].iter().all(|arg| arg != "--setenv"));
    let mut command = Command::new(&launch.argv[delimiter + 1]);
    command
        .args(&launch.argv[delimiter + 2..])
        .env_clear()
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let group = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
    let spill = tempfile::tempdir().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let output = group
        .wait_with_bounded_drain_budget(
            &DrainLimits {
                resident_bound: 64 * 1024,
                spill_dir: spill.path().to_owned(),
            },
            64 * 1024,
            || Instant::now() >= deadline,
        )
        .unwrap();
    assert!(Instant::now() < deadline, "jobserver command deadlocked");
    Output {
        status: output.status,
        stdout: output.stdout.resident().to_vec(),
        stderr: output.stderr.resident().to_vec(),
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

fn assert_exact_remaining_tokens(bridge: &JobserverBridge, tokens: usize) {
    let mut reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o4000) // Linux O_NONBLOCK, not inherited by the command.
        .open(&bridge.host_path)
        .unwrap();
    let mut actual = vec![0; tokens];
    reader.read_exact(&mut actual).unwrap();
    // Credit bytes are opaque: GNU make 4.3 returns '+' even when the worker
    // seeded '|'. Exact count, including no extra implicit slot, is authority.
    assert_eq!(
        reader.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "the command's implicit slot must not become another transferable token"
    );
}

#[test]
fn command_bridge_preserves_exact_environment_and_literal_arguments() {
    let home = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let mut bridge = JobserverBridge::mint(2, home.path()).unwrap();
    let startup = workspace.path().join("startup.sh");
    std::fs::write(&startup, "printf poisoned > startup-ran\n").unwrap();
    for pwd in [None, Some(""), Some("/declared/path")] {
        let mut env = environment(&bridge);
        env.extend([
            ("EMPTY".into(), String::new()),
            (
                "LITERAL".into(),
                " ' \" $HOME $(touch interpolated)\n雪".into(),
            ),
            ("ENV".into(), startup.display().to_string()),
            ("BASH_ENV".into(), startup.display().to_string()),
        ]);
        if let Some(value) = pwd {
            env.push(("PWD".into(), value.into()));
        }
        let output = run(
            &mut bridge,
            workspace.path(),
            env.clone(),
            "/usr/bin/env",
            &strings(&["-0"]),
        );
        assert!(output.status.success(), "{output:?}");
        let actual: BTreeMap<_, _> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let entry = std::str::from_utf8(entry).unwrap();
                let (name, value) = entry.split_once('=').unwrap();
                (name.to_owned(), value.to_owned())
            })
            .collect();
        assert_eq!(actual, env.into_iter().collect());
    }
    let args = strings(&[
        "",
        "a b",
        "\"'",
        "$HOME",
        "$(touch interpolated)",
        "`touch interpolated`",
        "--",
        "a=b",
        "a\nb",
        "雪",
    ]);
    let env = environment(&bridge);
    let mut printf_args = strings(&["%s\\0"]);
    printf_args.extend(args.iter().cloned());
    let output = run(
        &mut bridge,
        workspace.path(),
        env,
        "/usr/bin/printf",
        &printf_args,
    );
    assert!(output.status.success(), "{output:?}");
    let expected = args
        .iter()
        .flat_map(|arg| arg.bytes().chain([0]))
        .collect::<Vec<_>>();
    assert_eq!(output.stdout, expected);
    assert!(!workspace.path().join("interpolated").exists());
    assert!(!workspace.path().join("startup-ran").exists());
    assert_exact_remaining_tokens(&bridge, 1);
}

#[test]
fn command_bridge_preserves_exit_status_and_signal() {
    let home = tempfile::tempdir().unwrap();
    let mut bridge = JobserverBridge::mint(1, home.path()).unwrap();
    for (script, code, signal) in [
        ("exit 37", Some(37), None),
        ("kill -TERM $$", None, Some(15)),
    ] {
        let env = environment(&bridge);
        let output = run(
            &mut bridge,
            home.path(),
            env,
            "/bin/sh",
            &strings(&["-c", script]),
        );
        assert_eq!(output.status.code(), code);
        assert_eq!(output.status.signal(), signal);
    }
    assert_exact_remaining_tokens(&bridge, 0);
}

#[test]
fn command_bridge_refuses_a_missing_fifo_before_running_the_command() {
    let home = tempfile::tempdir().unwrap();
    let mut bridge = JobserverBridge::mint(2, home.path()).unwrap();
    std::fs::remove_file(&bridge.host_path).unwrap();
    let env = environment(&bridge);
    let output = run(
        &mut bridge,
        home.path(),
        env,
        "/usr/bin/printf",
        &strings(&["must-not-execute"]),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn canonical_launch_refuses_stale_or_ambiguous_authority() {
    let home = tempfile::tempdir().unwrap();
    let bridge = JobserverBridge::mint(2, home.path()).unwrap();
    let mut spec = CanonicalNamespaceSpec::new();
    spec.env = environment(&bridge);
    let before = spec.clone();
    let launch = bridge
        .canonical_launch(&spec, &builder_support(), "cargo", &[])
        .unwrap();
    assert_eq!(spec, before, "the keyed final environment must stay intact");
    assert!(
        launch
            .argv
            .iter()
            .any(|arg| arg.as_os_str() == std::ffi::OsStr::new(&bridge.visible_path))
    );
    for (name, replacement) in [
        ("MAKEFLAGS", "-j2"),
        ("CARGO_MAKEFLAGS", bridge.makeflags()),
        ("NUM_JOBS", "20"),
    ] {
        let mut stale = spec.clone();
        stale.env.iter_mut().find(|(key, _)| key == name).unwrap().1 = replacement.into();
        assert!(
            bridge
                .canonical_launch(&stale, &builder_support(), "cargo", &[])
                .is_err()
        );
    }
    for extra in [
        ("MFLAGS", "-j99"),
        ("MAKEFLAGS", "-j2 --jobserver-auth=3,4"),
    ] {
        let mut stale = spec.clone();
        stale.env.push((extra.0.into(), extra.1.into()));
        assert!(
            bridge
                .canonical_launch(&stale, &builder_support(), "cargo", &[])
                .is_err()
        );
    }
    for program in ["", "command=assignment"] {
        assert!(
            bridge
                .canonical_launch(&spec, &builder_support(), program, &[])
                .is_err()
        );
    }
}

#[test]
fn native_make_build_shares_one_worker_budget_and_returns_every_token() {
    for tool in ["/usr/bin/make", "/usr/bin/cc", "/usr/bin/ar"] {
        if !Path::new(tool).is_file() {
            eprintln!("SKIP native jobserver fixture: {tool} unavailable");
            return;
        }
    }
    for grant in [1, 3] {
        let home = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let mut bridge = JobserverBridge::mint(grant, home.path()).unwrap();
        std::fs::write(
            workspace.path().join("answer.c"),
            "int answer(void) { return 42; }\n",
        )
        .unwrap();
        std::fs::write(workspace.path().join("main.c"), "#include <stdio.h>\nint answer(void);\nint main(void) { printf(\"%d\\n\", answer()); return 0; }\n").unwrap();
        std::fs::write(
            workspace.path().join("Makefile"),
            concat!(
                ".PHONY: all left right\n",
                "all: left right\n",
                "\t@$(AR) crs libanswer.a left-a.o\n",
                "\t@$(CC) main.c libanswer.a -o answer\n",
                "\t@./answer\n",
                "left right:\n",
                "\t+@$(MAKE) --no-print-directory -f child.mk PREFIX=$@\n",
            ),
        )
        .unwrap();
        std::fs::write(workspace.path().join("child.mk"), concat!(
            ".PHONY: all\n",
            "all: $(addprefix $(PREFIX)-,a.o b.o c.o)\n",
            "%.o:\n",
            "\t@printf 'start %s\\n' '$@'; sleep 0.05; $(CC) -c answer.c -o '$@' && printf 'end %s\\n' '$@'\n",
        )).unwrap();
        let mut env = environment(&bridge);
        env.extend([
            ("CC".into(), "/usr/bin/cc".into()),
            ("AR".into(), "/usr/bin/ar".into()),
            ("TMPDIR".into(), workspace.path().display().to_string()),
        ]);
        let output = run(
            &mut bridge,
            workspace.path(),
            env,
            "/usr/bin/make",
            &strings(&["--no-print-directory", "-f", "Makefile"]),
        );
        assert!(output.status.success(), "grant={grant}: {output:?}");
        assert!(
            output.stderr.is_empty(),
            "jobserver warning: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut active = BTreeSet::new();
        let mut started = BTreeSet::new();
        let mut peak = 0;
        let stdout = String::from_utf8(output.stdout).unwrap();
        for line in stdout.lines() {
            if let Some(job) = line.strip_prefix("start ") {
                assert!(started.insert(job), "duplicate compile: {line}");
                assert!(active.insert(job));
                peak = peak.max(active.len());
            } else if let Some(job) = line.strip_prefix("end ") {
                assert!(active.remove(job), "compile ended without starting: {line}");
            }
        }
        assert_eq!(started.len(), 6, "{stdout}");
        assert!(active.is_empty(), "{stdout}");
        assert!(
            peak <= grant as usize,
            "grant={grant}, peak={peak}: {stdout}"
        );
        if grant > 1 {
            assert!(
                peak > 1,
                "nested make silently lost usable parallelism: {stdout}"
            );
        }
        assert!(
            stdout.lines().any(|line| line == "42"),
            "native executable did not run: {stdout}"
        );
        assert!(
            std::fs::metadata(workspace.path().join("libanswer.a"))
                .unwrap()
                .len()
                > 0
        );
        assert_exact_remaining_tokens(&bridge, (grant - 1) as usize);
    }
}
